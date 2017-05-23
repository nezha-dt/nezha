//===- FuzzerLoop.cpp - Fuzzer's main loop --------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Fuzzer's main loop.
//===----------------------------------------------------------------------===//

#include "FuzzerInternal.h"
#include <algorithm>
#include <cstring>
#include <memory>

// To log differences natively within libFuzzer
#include <sstream>

#if defined(__has_include)
#if __has_include(<sanitizer / coverage_interface.h>)
#include <sanitizer/coverage_interface.h>
#endif
#if __has_include(<sanitizer / lsan_interface.h>)
#include <sanitizer/lsan_interface.h>
#endif
#endif

#define NO_SANITIZE_MEMORY
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#undef NO_SANITIZE_MEMORY
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize_memory))
#endif
#endif

namespace fuzzer {
static const size_t kMaxUnitSizeToPrint = 256;
static const size_t TruncateMaxRuns = 1000;

thread_local bool Fuzzer::IsMyThread;

// Track if a difference was encountered in the return values of this unit.
thread_local bool UnitHadDiff;


static void MissingExternalApiFunction(const char *FnName) {
  Printf("ERROR: %s is not defined. Exiting.\n"
         "Did you use -fsanitize-coverage=... to build your code?\n",
         FnName);
  exit(1);
}

#define CHECK_EXTERNAL_FUNCTION(fn)                                            \
  do {                                                                         \
    if (!(EF->fn))                                                             \
      MissingExternalApiFunction(#fn);                                         \
  } while (false)

// Only one Fuzzer per process.
static Fuzzer *F;

struct DiffController {

  // Returns true if the vector ret_v contains both at least one value that is
  // non-zero and one equal to 0. This means that there exists a library that
  // parses the Unit successfully and one that doesn't.
  static bool RetTupleHasRetDiff(std::vector<int>& ret_v) {
    bool has_zero = false;
    bool has_nonzero = false;
    std::stringstream SS;

    for (size_t i = 0; i < ret_v.size(); ++i) {
      if (ret_v[i] == 0)
        has_zero = true;
      else
        has_nonzero = true;
      SS << ret_v[i] << "_";
    }

    return has_zero && has_nonzero;
  }

  static bool IsNewRetTuple(const FuzzingOptions &Options,
                            Fuzzer::Diff *D, std::vector<int>& ret_v) {
      return D->SetOutputs.insert(ret_v).second;
  }

  static bool IsNewCovDiff(const FuzzingOptions &Options,
                           Fuzzer::Diff *D, std::vector<int>& cov_v) {
    return D->SetCovDiffs.insert(cov_v).second;
  }

  static bool IsNewEcDiff(const FuzzingOptions &Options,
                          Fuzzer::Diff *D, std::vector<int>& ec_v) {
    return D->SetRawEcDiffs.insert(ec_v).second;
  }

  static std::string VectorToString(std::vector<int> vec) {
    std::stringstream SS;

    for (auto &v : vec) {
      SS << std::hex << v;
      SS << "_";
    }

    return SS.str();
  }

  static std::vector<int> ParseGenericIntVector(ValContainerInt *vcont) {
    if (vcont && vcont->vals && vcont->size > 0) {
      std::vector<int> vcont_v = std::vector<int>(vcont->size);
      for (int i = 0; i < vcont->size; ++i) {
        vcont_v[i] = vcont->vals[i];
      }
      return vcont_v;
    }

    return std::vector<int>();
  }

  static void Reset(Fuzzer::Diff *D) {
    D->Reset();
  }
};

struct CoverageController {
  static void Reset() {
    CHECK_EXTERNAL_FUNCTION(__sanitizer_reset_coverage);
    EF->__sanitizer_reset_coverage();
    PcMapResetCurrent();
  }

  static void ResetCounters(const FuzzingOptions &Options) {
    if (Options.UseCounters) {
      EF->__sanitizer_update_counter_bitset_and_clear_counters(0);
    }
  }

  static void Prepare(const FuzzingOptions &Options, Fuzzer::Coverage *C) {
    if (Options.UseCounters) {
      size_t NumCounters = EF->__sanitizer_get_number_of_counters();
      C->CounterBitmap.resize(NumCounters);
    }
  }

  // Records data to a maximum coverage tracker. Returns true if additional
  // coverage was discovered.
  static bool RecordMax(const FuzzingOptions &Options, Fuzzer::Coverage *C) {
    bool Res = false;

    // Since we are resetting the coverage buffer for differential testing, we
    // need to manually compute global coverage by tracking global unique set of
    // PCs executed.
    uintptr_t *CoverageBuf;
    uint64_t CurrBlkCov = EF->__sanitizer_get_coverage_pc_buffer(&CoverageBuf);
    for (size_t I = 0; I < CurrBlkCov; ++I)
      C->PCSet.insert(CoverageBuf[I]);

    // Always reset coverage buffer after consuming it.
    Reset();

    uint64_t NewBlockCoverage = C->PCSet.size();
    if (NewBlockCoverage > C->BlockCoverage) {
      Res = true;
      C->BlockCoverage = NewBlockCoverage;
    }

    if (Options.UseIndirCalls &&
        EF->__sanitizer_get_total_unique_caller_callee_pairs) {
      uint64_t NewCallerCalleeCoverage =
          EF->__sanitizer_get_total_unique_caller_callee_pairs();
      if (NewCallerCalleeCoverage > C->CallerCalleeCoverage) {
        Res = true;
        C->CallerCalleeCoverage = NewCallerCalleeCoverage;
      }
    }

    if (Options.UseCounters) {
      if (Options.ForceDefault) {
        uint64_t CounterDelta =
        EF->__sanitizer_update_counter_bitset_and_clear_counters(
          C->CounterBitmap.data());
        if (CounterDelta > 0) {
          Res = true;
          C->CounterBitmapBits += CounterDelta;
        }
      } else {
        if (C->LastCounterDelta > 0) {
          Res = true;
          C->CounterBitmapBits += C->LastCounterDelta;
        }
      }
    }

    uint64_t NewPcMapBits = PcMapMergeInto(&C->PCMap);
    if (NewPcMapBits > C->PcMapBits) {
      Res = true;
      C->PcMapBits = NewPcMapBits;
    }

    if (NewBlockCoverage > C->PcBufferLen) {
      Res = true;
      C->PcBufferLen = NewBlockCoverage;
    }

    return Res;
  }
};

// Leak detection is expensive, so we first check if there were more mallocs
// than frees (using the sanitizer malloc hooks) and only then try to call lsan.
struct MallocFreeTracer {
  void Start() {
    Mallocs = 0;
    Frees = 0;
  }
  // Returns true if there were more mallocs than frees.
  bool Stop() { return Mallocs > Frees; }
  std::atomic<size_t> Mallocs;
  std::atomic<size_t> Frees;
};

static MallocFreeTracer AllocTracer;

void MallocHook(const volatile void *ptr, size_t size) {
  AllocTracer.Mallocs++;
}
void FreeHook(const volatile void *ptr) {
  AllocTracer.Frees++;
}

Fuzzer::Fuzzer(UserCallback CB, MutationDispatcher &MD, FuzzingOptions Options)
    : CB(CB), MD(MD), Options(Options) {
  SetDeathCallback();
  InitializeTraceState();
  assert(!F);
  F = this;
  ResetCoverage();
  ResetDiff();
  IsMyThread = true;
  if (Options.DetectLeaks && EF->__sanitizer_install_malloc_and_free_hooks)
    EF->__sanitizer_install_malloc_and_free_hooks(MallocHook, FreeHook);
}

void Fuzzer::LazyAllocateCurrentUnitData() {
  if (CurrentUnitData || Options.MaxLen == 0) return;
  CurrentUnitData = new uint8_t[Options.MaxLen];
}

void Fuzzer::SetDeathCallback() {
  CHECK_EXTERNAL_FUNCTION(__sanitizer_set_death_callback);
  EF->__sanitizer_set_death_callback(StaticDeathCallback);
}

void Fuzzer::StaticDeathCallback() {
  assert(F);
  F->DeathCallback();
}

void Fuzzer::DumpCurrentUnit(const char *Prefix) {
  if (!CurrentUnitData) return;  // Happens when running individual inputs.
  size_t UnitSize = CurrentUnitSize;
  if (UnitSize <= kMaxUnitSizeToPrint) {
    PrintHexArray(CurrentUnitData, UnitSize, "\n");
    PrintASCII(CurrentUnitData, UnitSize, "\n");
  }
  WriteUnitToFileWithPrefix({CurrentUnitData, CurrentUnitData + UnitSize},
                            Prefix);
}

NO_SANITIZE_MEMORY
void Fuzzer::DeathCallback() {
  DumpCurrentUnit("crash-");
  PrintFinalStats();
}

void Fuzzer::StaticAlarmCallback() {
  assert(F);
  F->AlarmCallback();
}

void Fuzzer::StaticCrashSignalCallback() {
  assert(F);
  F->CrashCallback();
}

void Fuzzer::StaticInterruptCallback() {
  assert(F);
  F->InterruptCallback();
}

void Fuzzer::CrashCallback() {
  Printf("==%d== ERROR: libFuzzer: deadly signal\n", GetPid());
  if (EF->__sanitizer_print_stack_trace)
    EF->__sanitizer_print_stack_trace();
  Printf("NOTE: libFuzzer has rudimentary signal handlers.\n"
         "      Combine libFuzzer with AddressSanitizer or similar for better "
         "crash reports.\n");
  Printf("SUMMARY: libFuzzer: deadly signal\n");
  DumpCurrentUnit("crash-");
  PrintFinalStats();
  exit(Options.ErrorExitCode);
}

void Fuzzer::InterruptCallback() {
  Printf("==%d== libFuzzer: run interrupted; exiting\n", GetPid());
  PrintFinalStats();
  _Exit(0);  // Stop right now, don't perform any at-exit actions.
}

NO_SANITIZE_MEMORY
void Fuzzer::AlarmCallback() {
  assert(Options.UnitTimeoutSec > 0);
  if (!InFuzzingThread()) return;
  if (!CurrentUnitSize)
    return; // We have not started running units yet.
  size_t Seconds =
      duration_cast<seconds>(system_clock::now() - UnitStartTime).count();
  if (Seconds == 0)
    return;
  if (Options.Verbosity >= 2)
    Printf("AlarmCallback %zd\n", Seconds);
  if (Seconds >= (size_t)Options.UnitTimeoutSec) {
    Printf("ALARM: working on the last Unit for %zd seconds\n", Seconds);
    Printf("       and the timeout value is %d (use -timeout=N to change)\n",
           Options.UnitTimeoutSec);
    DumpCurrentUnit("timeout-");
    Printf("==%d== ERROR: libFuzzer: timeout after %d seconds\n", GetPid(),
           Seconds);
    if (EF->__sanitizer_print_stack_trace)
      EF->__sanitizer_print_stack_trace();
    Printf("SUMMARY: libFuzzer: timeout\n");
    PrintFinalStats();
    _Exit(Options.TimeoutExitCode); // Stop right now.
  }
}

void Fuzzer::RssLimitCallback() {
  Printf(
      "==%d== ERROR: libFuzzer: out-of-memory (used: %zdMb; limit: %zdMb)\n",
      GetPid(), GetPeakRSSMb(), Options.RssLimitMb);
  Printf("   To change the out-of-memory limit use -rss_limit_mb=<N>\n\n");
  if (EF->__sanitizer_print_memory_profile)
    EF->__sanitizer_print_memory_profile(50);
  DumpCurrentUnit("oom-");
  Printf("SUMMARY: libFuzzer: out-of-memory\n");
  PrintFinalStats();
  _Exit(Options.ErrorExitCode); // Stop right now.
}

void Fuzzer::PrintStats(const char *Where, const char *End) {
  size_t ExecPerSec = execPerSec();
  if (Options.OutputCSV) {
    static bool csvHeaderPrinted = false;
    if (!csvHeaderPrinted) {
      csvHeaderPrinted = true;
      Printf("runs,block_cov,bits,cc_cov,corpus,execs_per_sec,tbms,reason\n");
    }
    Printf("%zd,%zd,%zd,%zd,%zd,%zd,%s\n", TotalNumberOfRuns,
           MaxCoverage.BlockCoverage, MaxCoverage.CounterBitmapBits,
           MaxCoverage.CallerCalleeCoverage, Corpus.size(), ExecPerSec, Where);
  }

  if (!Options.Verbosity)
    return;
  Printf("#%zd\t%s", TotalNumberOfRuns, Where);
  if (MaxCoverage.BlockCoverage)
    Printf(" cov: %zd", MaxCoverage.BlockCoverage);
  if (MaxCoverage.PcMapBits)
    Printf(" path: %zd", MaxCoverage.PcMapBits);
  if (auto TB = MaxCoverage.CounterBitmapBits)
    Printf(" bits: %zd", TB);
  if (MaxCoverage.CallerCalleeCoverage)
    Printf(" indir: %zd", MaxCoverage.CallerCalleeCoverage);
  Printf(" units: %zd exec/s: %zd", Corpus.size(), ExecPerSec);
  Printf("%s", End);
}

void Fuzzer::PrintFinalStats() {
  if (!Options.PrintFinalStats) return;
  size_t ExecPerSec = execPerSec();

  std::string mode = "";
  if (Options.GlobalCoverage)
    mode += "GlobalCoverage |";
  if (Options.PDCoarse)
    mode = "PDCoarse";
  if (Options.PDFine)
    mode = "PDFine";
  if (Options.OD)
    mode = "OD";

  if (Options.OD ||
      Options.PDCoarse ||
      Options.PDFine ||
      Options.GlobalCoverage) {
    Printf("stat::mode:                     | %s\n", mode.c_str());
  } else {
    Printf("stat::mode:                     Default\n");
  }

  if (!Options.ForceDefault)
    Printf("stat::number_of_diffs:          %zd\n", TotalNumberOfDiffs);
  Printf("stat::number_of_executed_units: %zd\n", TotalNumberOfRuns);
  Printf("stat::average_exec_per_sec:     %zd\n", ExecPerSec);
  Printf("stat::new_units_added:          %zd\n", NumberOfNewUnitsAdded);
  Printf("stat::slowest_unit_time_sec:    %zd\n", TimeOfLongestUnitInSeconds);
  Printf("stat::peak_rss_mb:              %zd\n", GetPeakRSSMb());
}

size_t Fuzzer::MaxUnitSizeInCorpus() const {
  size_t Res = 0;
  for (auto &X : Corpus)
    Res = std::max(Res, X.size());
  return Res;
}

void Fuzzer::SetMaxLen(size_t MaxLen) {
  assert(Options.MaxLen == 0); // Can only reset MaxLen from 0 to non-0.
  assert(MaxLen);
  Options.MaxLen = MaxLen;
  Printf("INFO: -max_len is not provided, using %zd\n", Options.MaxLen);
}


void Fuzzer::RereadOutputCorpus(size_t MaxSize) {
  if (Options.OutputCorpus.empty())
    return;
  std::vector<Unit> AdditionalCorpus;
  ReadDirToVectorOfUnits(Options.OutputCorpus.c_str(), &AdditionalCorpus,
                         &EpochOfLastReadOfOutputCorpus, MaxSize);
  if (Corpus.empty()) {
    Corpus = AdditionalCorpus;
    return;
  }
  if (!Options.Reload)
    return;
  if (Options.Verbosity >= 2)
    Printf("Reload: read %zd new units.\n", AdditionalCorpus.size());
  for (auto &X : AdditionalCorpus) {
    if (X.size() > MaxSize)
      X.resize(MaxSize);
    if (UnitHashesAddedToCorpus.insert(Hash(X)).second) {
      if (RunOne(X)) {
        Corpus.push_back(X);
        UpdateCorpusDistribution();
        PrintStats("RELOAD");
      }
    }
  }
}

void Fuzzer::ShuffleCorpus(UnitVector *V) {
  std::random_shuffle(V->begin(), V->end(), MD.GetRand());
  if (Options.PreferSmall)
    std::stable_sort(V->begin(), V->end(), [](const Unit &A, const Unit &B) {
      return A.size() < B.size();
    });
}

// Tries random prefixes of corpus items.
// Prefix length is chosen according to exponential distribution
// to sample short lengths much more heavily.
void Fuzzer::TruncateUnits(std::vector<Unit> *NewCorpus) {
  size_t MaxCorpusLen = 0;
  for (const auto &U : Corpus)
    MaxCorpusLen = std::max(MaxCorpusLen, U.size());

  if (MaxCorpusLen <= 1)
    return;

  // 50% of exponential distribution is Log[2]/lambda.
  // Choose lambda so that median is MaxCorpusLen / 2.
  double Lambda = 2.0 * log(2.0) / static_cast<double>(MaxCorpusLen);
  std::exponential_distribution<> Dist(Lambda);
  std::vector<double> Sizes;
  size_t TruncatePoints = std::max(1ul, TruncateMaxRuns / Corpus.size());
  Sizes.reserve(TruncatePoints);
  for (size_t I = 0; I < TruncatePoints; ++I) {
    Sizes.push_back(Dist(MD.GetRand().Get_mt19937()) + 1);
  }
  std::sort(Sizes.begin(), Sizes.end());

  for (size_t S : Sizes) {
    for (const auto &U : Corpus) {
      if (S < U.size() && RunOne(U.data(), S)) {
        Unit U1(U.begin(), U.begin() + S);
        NewCorpus->push_back(U1);
        WriteToOutputCorpus(U1);
        PrintStatusForNewUnit(U1);
      }
    }
  }
  PrintStats("TRUNC  ");
}

void Fuzzer::ShuffleAndMinimize() {
  PrintStats("READ  ");
  std::vector<Unit> NewCorpus;
  if (Options.ShuffleAtStartUp)
    ShuffleCorpus(&Corpus);

  // ASAN coverage tracker includes PC executed during the initialization.
  // Execute the fuzzer with the first unit to exercise this code, so that we
  // can reset the coverage.

  if (Options.TruncateUnits) {
    ResetCoverage();
    ResetDiff();
    TruncateUnits(&NewCorpus);
  }

  ResetCoverage();
  ResetDiff();

  for (const auto &U : Corpus) {
    bool NewCoverage = RunOne(U);
    if (!Options.PruneCorpus || NewCoverage) {
      NewCorpus.push_back(U);
      if (Options.Verbosity >= 2)
        Printf("NEW0: %zd L %zd\n", MaxCoverage.BlockCoverage, U.size());
    }
    TryDetectingAMemoryLeak(U.data(), U.size(),
                            /*DuringInitialCorpusExecution*/ true);
  }
  Corpus = NewCorpus;
  UpdateCorpusDistribution();
  for (auto &X : Corpus)
    UnitHashesAddedToCorpus.insert(Hash(X));
  PrintStats("INITED");
  if (Corpus.empty()) {
    Printf("ERROR: no interesting inputs were found. "
           "Is the code instrumented for coverage? Exiting.\n");
    exit(1);
  }
}

bool Fuzzer::UpdateMaxCoverage() {
  if (Options.OD)
    return false;
  uintptr_t PrevBufferLen = MaxCoverage.PcBufferLen;
  bool Res = CoverageController::RecordMax(Options, &MaxCoverage);

  if (Options.PrintNewCovPcs && PrevBufferLen != MaxCoverage.PcBufferLen) {
    uintptr_t *CoverageBuf;
    EF->__sanitizer_get_coverage_pc_buffer(&CoverageBuf);
    assert(CoverageBuf);
    for (size_t I = PrevBufferLen; I < MaxCoverage.PcBufferLen; ++I) {
      Printf("%p\n", CoverageBuf[I]);
    }
  }

  return Res;
}

bool Fuzzer::UpdateDiffAndLog(const uint8_t *Data, size_t Size) {

  // Returns true if a differential-based metric indicates that we should add
  // this unit to the corpus
  bool Res;

  // Unit demonstrates difference in path SET cardinality across programs.
  bool PathSetCovDiff = false;

  // Unit demonstrates difference in path RAW cardinality across programs.
  bool PathRawCovDiff = false;

  // Unit showed new unique tuple of return values
  // (-1, -2, 1, -11)
  bool NewRetTuple   = false;

  // Unit has a mixed accept/reject ret
  // (0, 1, 1, -11)
  bool HasRetDiff    = false;

  // Unit showed new unique tuple of PC paths
  bool NewPathTuple  = false;

  uintptr_t *CoverageBuf = NULL;
  ValContainerU64 *vcont64 = NULL;

  std::stringstream Prefix;
  // Size of per-lib path consisting of SET of edges.
  std::vector<int> PathSetSize;

  // Size of per-lib path consisting of RAW edges.
  std::vector<int> PathRawSize;

  // Path to be stored in set.
  std::string Vpath = "";
  // Path to be used in output name.
  std::string Fpath = "";
  std::string H;
  uint64_t Sz64, SzIdx;
  std::string PrefixParent;
  double ScoreUnit;

  // Global PC buffer
  EF->__sanitizer_get_coverage_pc_buffer(&CoverageBuf);
  
  // Indexes to the global PC buffer (start, end).
  // Track the per-lib list of unique PCs executed.
  vcont64 = EF->LLVMFuzzerCovBuffers();
  
  if (vcont64) {
    for (size_t I = 0; I < vcont64->size - 1; ++I) {
      SzIdx = vcont64->vals[I + 1] - vcont64->vals[I];
      H = fuzzer::HashSha1((uint8_t *)(CoverageBuf + vcont64->vals[I]),
                           SzIdx * sizeof(uint64_t));
      Fpath += (H).substr(0, 5) + "_";
      Vpath += H + "_";
      PathSetSize.push_back(SzIdx);
    }
    
    // Update global view for bit counts
    MaxCoverage.LastCounterDelta = 0;
    ValContainerInt *vcont_bc = EF->LLVMFuzzerBitcounts();
    assert(vcont_bc && vcont_bc->vals);
    for (int I = 0; I < PathSetSize.size(); ++I) {
      PathRawSize.push_back(PathSetSize[I] + vcont_bc->vals[I]);
      MaxCoverage.LastCounterDelta += vcont_bc->vals[I];
    }
  }

  // Vector of return values from all libraries.
  ValContainerInt *vcont = EF->LLVMFuzzerNezhaOutputs();
  assert(vcont && vcont->vals);
  std::vector<int> ret_v = DiffController::ParseGenericIntVector(vcont);
  assert(!ret_v.empty());
  HasRetDiff = DiffController::RetTupleHasRetDiff(ret_v);

  // Log difference with fuzzy hash bucketing.
  bool IsNewDiff = false;
  if (HasRetDiff) {

    // Compute fuzzy similarity score normalized by number of libraries.
    std::vector<std::string> HCandidate;
    std::string HLib;
    uint64_t sz;
    if (vcont64) {
      for (size_t I = 0; I < vcont64->size - 1; ++I) {
        sz = (vcont64->vals[I + 1] - vcont64->vals[I]) * sizeof(uint64_t);
        HLib = fuzzer::HashFuzzy((uint8_t *)(CoverageBuf + vcont64->vals[I]), sz);
        HCandidate.push_back(HLib);
      }
      assert(!HCandidate.empty());
    }

    IsNewDiff = true;
    for (auto FHashPair: DiffStats.DiffHashes) {
      auto FHashVec = FHashPair.second.first;
      auto FRetVec = FHashPair.second.second;
      int I = 0;

      ScoreUnit = 0;
      for (auto FHashLib: FHashVec)
        ScoreUnit += fuzzer::HashFuzzy_cmp(FHashLib, HCandidate[I++]);
      ScoreUnit /= FHashVec.size();
      
      // Lower the score, the less similar this test case is from the rest.
      // Bucket this difference with another similar one if (1) they are similar
      // enough w.r.t. the fuzzy hashes and (2) their return values match.
      if ((std::equal(FRetVec.begin(), FRetVec.end(), ret_v.begin())) &&
          (ScoreUnit > Options.DiffFhashMin)) {
        IsNewDiff = false;
        PrefixParent = FHashPair.first;
        break;
      }
    }

    if (IsNewDiff) {
      // Log new difference.
      Prefix << DiffController::VectorToString(ret_v);
      Prefix << Fpath << TotalNumberOfRuns << "_";
      std::stringstream PrefixToStore;
      PrefixToStore << Prefix.str() << Hash({Data, Data + Size});
      DiffStats.DiffHashes.push_back(
        std::make_pair(PrefixToStore.str(), std::make_pair(HCandidate, ret_v)));
      TotalNumberOfDiffs++;
      UnitHadDiff = true;
    } else {
      Prefix << PrefixParent << "_";
      Prefix << TotalNumberOfRuns << "_";
      Prefix << (int)ScoreUnit << "_";
    }
    if ((IsNewDiff) || (!Options.LogUnique) || (!vcont64 && HasRetDiff))
      WriteUnitToFileWithPrefix({Data, Data + Size}, Prefix.str().c_str());
  }


  //////
  //
  // Output Diversity
  //    Track number of unique output (return values) tuples observed so far.
  //
  if (Options.OD)
    NewRetTuple = DiffController::IsNewRetTuple(Options, &DiffStats, ret_v);

  //////
  //
  // Path Diversity Coarse
  //    Track number of unique tuples of per-lib path raw cardinality.
  //
  // NOTE: Path can contain duplicate edges. We achieve this by including the
  //       edge counts.
  //
  if (Options.PDCoarse) {
    ValContainerInt *vcontint = EF->LLVMFuzzerEdgecounts();
    assert(vcontint && vcontint->vals);
    std::vector<int> ec_v = DiffController::ParseGenericIntVector(vcontint);
    PathRawCovDiff = DiffController::IsNewEcDiff(Options, &DiffStats, ec_v);
  }

  //////
  //
  // Fitness_PD: Coverage Path Diversity
  //    Track number of unique tuples of per-lib path edge set.
  //
  // NOTE: Vpath comprises unique edges.
  //
  if (Options.PDFine) {
    if (DiffStats.SetCovPaths.insert(Vpath).second)
      NewPathTuple = true;
  }


  Res = NewRetTuple | PathSetCovDiff | PathRawCovDiff | NewPathTuple;
  if ((Options.Verbosity > 2) && Res)
    Printf("ADD_TO_CORPUS:  Ret:%d, CovSet:%d, CovRaw:%d, Path:%d\n",
           NewRetTuple, PathSetCovDiff, PathRawCovDiff, NewPathTuple);

  return Res;
}

bool Fuzzer::RunOne(const uint8_t *Data, size_t Size) {
  bool Res;
  TotalNumberOfRuns++;

  // TODO(aizatsky): this Reset call seems to be not needed.
  CoverageController::ResetCounters(Options);

  ExecuteCallback(Data, Size);
  if (!Options.ForceDefault) {
    UnitHadDiff = false;

    // In differential testing mode,
    //  (1) Log any differences,
    //  (2) Res returns true if the unit shows an improvement for the desired
    //      fitness function(s).
    Res = UpdateDiffAndLog(Data, Size);
    if (!Options.OD) {
      bool HasNewUnionCov = UpdateMaxCoverage();
      if (Options.GlobalCoverage)
        Res |= HasNewUnionCov;
    }

  } else {

    // In default mode, add unit if global coverage increases.
    Res = UpdateMaxCoverage();
  }

  auto UnitStopTime = system_clock::now();
  auto TimeOfUnit =
      duration_cast<seconds>(UnitStopTime - UnitStartTime).count();
  if (!(TotalNumberOfRuns & (TotalNumberOfRuns - 1)) &&
      secondsSinceProcessStartUp() >= 2)
    PrintStats("pulse ");
  if (TimeOfUnit > TimeOfLongestUnitInSeconds &&
      TimeOfUnit >= Options.ReportSlowUnits) {
    TimeOfLongestUnitInSeconds = TimeOfUnit;
    Printf("Slowest unit: %zd s:\n", TimeOfLongestUnitInSeconds);
    WriteUnitToFileWithPrefix({Data, Data + Size}, "slow-unit-");
  }
  return Res;
}

void Fuzzer::RunOneAndUpdateCorpus(const uint8_t *Data, size_t Size) {
  if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
    return;
  if (RunOne(Data, Size))
    ReportNewCoverage({Data, Data + Size});
}

size_t Fuzzer::GetCurrentUnitInFuzzingThead(const uint8_t **Data) const {
  assert(InFuzzingThread());
  *Data = CurrentUnitData;
  return CurrentUnitSize;
}

void Fuzzer::ExecuteCallback(const uint8_t *Data, size_t Size) {
  assert(InFuzzingThread());
  LazyAllocateCurrentUnitData();
  UnitStartTime = system_clock::now();
  // We copy the contents of Unit into a separate heap buffer
  // so that we reliably find buffer overflows in it.
  std::unique_ptr<uint8_t[]> DataCopy(new uint8_t[Size]);
  memcpy(DataCopy.get(), Data, Size);
  if (CurrentUnitData && CurrentUnitData != Data)
    memcpy(CurrentUnitData, Data, Size);
  AssignTaintLabels(DataCopy.get(), Size);
  CurrentUnitSize = Size;
  AllocTracer.Start();
  int Res = CB(DataCopy.get(), Size);
  (void)Res;
  HasMoreMallocsThanFrees = AllocTracer.Stop();
  CurrentUnitSize = 0;
  assert(Res == 0);
}

std::string Fuzzer::Coverage::DebugString() const {
  std::string Result =
      std::string("Coverage{") + "BlockCoverage=" +
      std::to_string(BlockCoverage) + " CallerCalleeCoverage=" +
      std::to_string(CallerCalleeCoverage) + " CounterBitmapBits=" +
      std::to_string(CounterBitmapBits) + " PcMapBits=" +
      std::to_string(PcMapBits) + "}";
  return Result;
}

void Fuzzer::WriteToOutputCorpus(const Unit &U) {
  if (Options.OnlyASCII)
    assert(IsASCII(U));
  if (Options.OutputCorpus.empty())
    return;
  std::string Path = DirPlusFile(Options.OutputCorpus, Hash(U));
  WriteToFile(U, Path);
  if (Options.Verbosity >= 2)
    Printf("Written to %s\n", Path.c_str());
}

void Fuzzer::WriteUnitToFileWithPrefix(const Unit &U, const char *Prefix) {
  if (!Options.SaveArtifacts)
    return;
  std::string Path = Options.ArtifactPrefix + Prefix + Hash(U);
  if (!Options.ExactArtifactPath.empty())
    Path = Options.ExactArtifactPath; // Overrides ArtifactPrefix.
  WriteToFile(U, Path);
  Printf("artifact_prefix='%s'; Test unit written to %s\n",
         Options.ArtifactPrefix.c_str(), Path.c_str());
  if (U.size() <= kMaxUnitSizeToPrint)
    Printf("Base64: %s\n", Base64(U).c_str());
}

void Fuzzer::SaveCorpus() {
  if (Options.OutputCorpus.empty())
    return;
  for (const auto &U : Corpus)
    WriteToFile(U, DirPlusFile(Options.OutputCorpus, Hash(U)));
  if (Options.Verbosity)
    Printf("Written corpus of %zd files to %s\n", Corpus.size(),
           Options.OutputCorpus.c_str());
}

void Fuzzer::PrintStatusForNewUnit(const Unit &U) {
  if (!Options.PrintNEW)
    return;
  PrintStats("NEW   ", "");
  if (Options.Verbosity) {
    Printf(" L: %zd ", U.size());
    MD.PrintMutationSequence();
    Printf("\n");
  }
}

void Fuzzer::ReportNewCoverage(const Unit &U) {
  Corpus.push_back(U);
  UpdateCorpusDistribution();
  UnitHashesAddedToCorpus.insert(Hash(U));
  MD.RecordSuccessfulMutationSequence();
  PrintStatusForNewUnit(U);
  WriteToOutputCorpus(U);
  NumberOfNewUnitsAdded++;
}

// Finds minimal number of units in 'Extra' that add coverage to 'Initial'.
// We do it by actually executing the units, sometimes more than once,
// because we may be using different coverage-like signals and the only
// common thing between them is that we can say "this unit found new stuff".
UnitVector Fuzzer::FindExtraUnits(const UnitVector &Initial,
                                  const UnitVector &Extra) {
  UnitVector Res = Extra;
  size_t OldSize = Res.size();
  for (int Iter = 0; Iter < 10; Iter++) {
    ShuffleCorpus(&Res);
    ResetCoverage();
    ResetDiff();

    for (auto &U : Initial)
      RunOne(U);

    Corpus.clear();
    for (auto &U : Res)
      if (RunOne(U))
        Corpus.push_back(U);

    char Stat[7] = "MIN   ";
    Stat[3] = '0' + Iter;
    PrintStats(Stat);

    size_t NewSize = Corpus.size();
    assert(NewSize <= OldSize);
    Res.swap(Corpus);

    if (NewSize + 5 >= OldSize)
      break;
    OldSize = NewSize;
  }
  return Res;
}

void Fuzzer::Merge(const std::vector<std::string> &Corpora) {
  if (Corpora.size() <= 1) {
    Printf("Merge requires two or more corpus dirs\n");
    return;
  }
  std::vector<std::string> ExtraCorpora(Corpora.begin() + 1, Corpora.end());

  assert(Options.MaxLen > 0);
  UnitVector Initial, Extra;
  ReadDirToVectorOfUnits(Corpora[0].c_str(), &Initial, nullptr, Options.MaxLen);
  for (auto &C : ExtraCorpora)
    ReadDirToVectorOfUnits(C.c_str(), &Extra, nullptr, Options.MaxLen);

  if (!Initial.empty()) {
    Printf("=== Minimizing the initial corpus of %zd units\n", Initial.size());
    Initial = FindExtraUnits({}, Initial);
  }

  Printf("=== Merging extra %zd units\n", Extra.size());
  auto Res = FindExtraUnits(Initial, Extra);

  for (auto &U: Res)
    WriteToOutputCorpus(U);

  Printf("=== Merge: written %zd units\n", Res.size());
}

// Tries detecting a memory leak on the particular input that we have just
// executed before calling this function.
void Fuzzer::TryDetectingAMemoryLeak(const uint8_t *Data, size_t Size,
                                     bool DuringInitialCorpusExecution) {
  if (!HasMoreMallocsThanFrees) return;  // mallocs==frees, a leak is unlikely.
  if (!Options.DetectLeaks) return;
  if (!&(EF->__lsan_enable) || !&(EF->__lsan_disable) ||
      !(EF->__lsan_do_recoverable_leak_check))
    return;  // No lsan.
  // Run the target once again, but with lsan disabled so that if there is
  // a real leak we do not report it twice.
  EF->__lsan_disable();
  RunOne(Data, Size);
  EF->__lsan_enable();
  if (!HasMoreMallocsThanFrees) return;  // a leak is unlikely.
  if (NumberOfLeakDetectionAttempts++ > 1000) {
    Options.DetectLeaks = false;
    Printf("INFO: libFuzzer disabled leak detection after every mutation.\n"
           "      Most likely the target function accumulates allocated\n"
           "      memory in a global state w/o actually leaking it.\n"
           "      If LeakSanitizer is enabled in this process it will still\n"
           "      run on the process shutdown.\n");
    return;
  }
  // Now perform the actual lsan pass. This is expensive and we must ensure
  // we don't call it too often.
  if (EF->__lsan_do_recoverable_leak_check()) { // Leak is found, report it.
    if (DuringInitialCorpusExecution)
      Printf("\nINFO: a leak has been found in the initial corpus.\n\n");
    Printf("INFO: to ignore leaks on libFuzzer side use -detect_leaks=0.\n\n");
    CurrentUnitSize = Size;
    DumpCurrentUnit("leak-");
    PrintFinalStats();
    _Exit(Options.ErrorExitCode);  // not exit() to disable lsan further on.
  }
}

void Fuzzer::MutateAndTestOne() {
  LazyAllocateCurrentUnitData();
  MD.StartMutationSequence();

  auto &U = ChooseUnitToMutate();
  assert(CurrentUnitData);
  size_t Size = U.size();
  assert(Size <= Options.MaxLen && "Oversized Unit");
  memcpy(CurrentUnitData, U.data(), Size);

  uint8_t *PreviousUnit = new uint8_t[Options.MaxLen];
  size_t PreviousSize = 0;

  for (int i = 0; i < Options.MutateDepth; i++) {
    memcpy(PreviousUnit, CurrentUnitData, Size);
    PreviousSize = Size;

    size_t NewSize = 0;
    NewSize = MD.Mutate(CurrentUnitData, Size, Options.MaxLen);
    assert(NewSize > 0 && "Mutator returned empty unit");
    assert(NewSize <= Options.MaxLen &&
           "Mutator return overisized unit");
    Size = NewSize;
    if (i == 0)
      StartTraceRecording();
    RunOneAndUpdateCorpus(CurrentUnitData, Size);
    StopTraceRecording();
    TryDetectingAMemoryLeak(CurrentUnitData, Size,
                            /*DuringInitialCorpusExecution*/ false);

    // Track and log previous unit.
    if (UnitHadDiff) {
      std::string s = fuzzer::HashSha1((uint8_t *)(CurrentUnitData), Size);
      s += "_BeforeMutationWas_";
      WriteUnitToFileWithPrefix({PreviousUnit, PreviousUnit + PreviousSize},
                                s.c_str());
    }
  }

  delete[] PreviousUnit;
}

// Returns an index of random unit from the corpus to mutate.
// Hypothesis: units added to the corpus last are more likely to be interesting.
// This function gives more weight to the more recent units.
size_t Fuzzer::ChooseUnitIdxToMutate() {
  size_t Idx =
      static_cast<size_t>(CorpusDistribution(MD.GetRand().Get_mt19937()));
  assert(Idx < Corpus.size());
  return Idx;
}

void Fuzzer::ResetCoverage() {
  CoverageController::Reset();
  MaxCoverage.Reset();
  CoverageController::Prepare(Options, &MaxCoverage);
}

void Fuzzer::ResetDiff() {
  DiffController::Reset(&DiffStats);
}

// Experimental search heuristic: drilling.
// - Read, shuffle, execute and minimize the corpus.
// - Choose one random unit.
// - Reset the coverage.
// - Start fuzzing as if the chosen unit was the only element of the corpus.
// - When done, reset the coverage again.
// - Merge the newly created corpus into the original one.
void Fuzzer::Drill() {
  // The corpus is already read, shuffled, and minimized.
  assert(!Corpus.empty());
  Options.PrintNEW = false; // Don't print NEW status lines when drilling.

  Unit U = ChooseUnitToMutate();

  ResetCoverage();
  ResetDiff();

  std::vector<Unit> SavedCorpus;
  SavedCorpus.swap(Corpus);
  Corpus.push_back(U);
  UpdateCorpusDistribution();
  assert(Corpus.size() == 1);
  RunOne(U);
  PrintStats("DRILL ");
  std::string SavedOutputCorpusPath; // Don't write new units while drilling.
  SavedOutputCorpusPath.swap(Options.OutputCorpus);
  Loop();

  ResetCoverage();
  ResetDiff();

  PrintStats("REINIT");
  SavedOutputCorpusPath.swap(Options.OutputCorpus);
  for (auto &U : SavedCorpus)
    RunOne(U);
  PrintStats("MERGE ");
  Options.PrintNEW = true;
  size_t NumMerged = 0;
  for (auto &U : Corpus) {
    if (RunOne(U)) {
      PrintStatusForNewUnit(U);
      NumMerged++;
      WriteToOutputCorpus(U);
    }
  }
  PrintStats("MERGED");
  if (NumMerged && Options.Verbosity)
    Printf("Drilling discovered %zd new units\n", NumMerged);
}

void Fuzzer::CheckDiffBasedFuncs() {
  if (Options.ForceDefault)
    return;

  if (Options.OD) {
    CHECK_EXTERNAL_FUNCTION(LLVMFuzzerNezhaOutputs && "LLVMFuzzerNezhaOutputs missing");
  } else {
    CHECK_EXTERNAL_FUNCTION(LLVMFuzzerBitcounts && "LLVMFuzzerBitcounts missing");
    CHECK_EXTERNAL_FUNCTION(LLVMFuzzerCovBuffers && "LLVMFuzzerCovBuffers missing");
  }

  // Will not reach here if there is an error.
}

void Fuzzer::Loop() {
  CheckDiffBasedFuncs();

  system_clock::time_point LastCorpusReload = system_clock::now();
  if (Options.DoCrossOver)
    MD.SetCorpus(&Corpus);
  while (true) {
    auto Now = system_clock::now();
    if (duration_cast<seconds>(Now - LastCorpusReload).count()) {
      RereadOutputCorpus(Options.MaxLen);
      LastCorpusReload = Now;
    }
    if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
      break;
    if (Options.MaxTotalTimeSec > 0 &&
        secondsSinceProcessStartUp() >
            static_cast<size_t>(Options.MaxTotalTimeSec))
      break;
    // Perform several mutations and runs.
    MutateAndTestOne();
  }

  PrintStats("DONE  ", "\n");
  MD.PrintRecommendedDictionary();
}

void Fuzzer::UpdateCorpusDistribution() {
  size_t N = Corpus.size();
  std::vector<double> Intervals(N + 1);
  std::vector<double> Weights(N);
  std::iota(Intervals.begin(), Intervals.end(), 0);
  std::iota(Weights.begin(), Weights.end(), 1);
  CorpusDistribution = std::piecewise_constant_distribution<double>(
      Intervals.begin(), Intervals.end(), Weights.begin());
}

} // namespace fuzzer

extern "C" {

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  assert(fuzzer::F);
  return fuzzer::F->GetMD().DefaultMutate(Data, Size, MaxSize);
}
}  // extern "C"
