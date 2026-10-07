// Standalone model of CBlockIndexWorkComparator, current and patched.
// The set is read with rbegin(), so the LAST element is the best candidate;
// operator() returns true when `pa` is WORSE than `pb`.
#include <cstdint>
#include <set>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

struct Idx {
    uint64_t nChainWork;
    int32_t  nSequenceId;
    uint32_t m_spam_score;
    std::string name;
};

static constexpr uint32_t LATE = 0xFFFFFFFFu;
static bool g_spam_tiebreak = false;

struct Cmp {
    bool operator()(const Idx* pa, const Idx* pb) const {
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        if (g_spam_tiebreak && pa->m_spam_score != pb->m_spam_score) {
            return pa->m_spam_score > pb->m_spam_score;   // more spam == worse
        }

        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        if (pa < pb) return false;
        if (pa > pb) return true;
        return false;
    }
};

static int failures = 0;
static void ck(const std::string& name, bool ok) {
    std::cout << "  [" << (ok ? "ok  " : "FAIL") << "] " << name << "\n";
    if (!ok) failures++;
}

static const Idx* best(std::vector<Idx*> v) {
    std::set<Idx*, Cmp> s(v.begin(), v.end());
    return *s.rbegin();                       // best candidate
}

int main() {
    // A arrived first, is spam-heavy.  B arrived second, is clean.
    Idx A{100, 1, 5000, "A_spammy_first"};
    Idx B{100, 2,    0, "B_clean_second"};

    g_spam_tiebreak = false;
    ck("disabled: first-seen wins (A)", best({&A,&B})->name == "A_spammy_first");

    g_spam_tiebreak = true;
    ck("enabled: clean block wins (B)", best({&A,&B})->name == "B_clean_second");

    // work must still dominate spam
    Idx C{101, 9, 9999, "C_spammy_more_work"};
    ck("more work beats cleaner block", best({&B,&C})->name == "C_spammy_more_work");

    // equal spam falls through to first-seen
    Idx D{100, 3, 0, "D_clean_third"};
    ck("equal spam -> first-seen (B before D)", best({&B,&D})->name == "B_clean_second");

    // ---- the race window, enforced via eligibility
    // Late straggler: clean, but arrived outside the window -> not eligible.
    Idx L{100, 4, LATE, "L_clean_late"};
    Idx S{100, 1, 5000, "S_spammy_incumbent"};
    g_spam_tiebreak = true;
    ck("late clean block does NOT displace incumbent",
       best({&S,&L})->name == "S_spammy_incumbent");

    // Same pair, but arriving inside the window -> eligible, and it wins.
    Idx L2{100, 4, 0, "L2_clean_in_window"};
    ck("clean block inside window DOES win",
       best({&S,&L2})->name == "L2_clean_in_window");

    // A late SPAMMY block must not displace a clean incumbent either.
    Idx CleanInc{100, 1, 0, "clean_incumbent"};
    Idx SpamLate{100, 4, LATE, "spammy_late"};
    ck("late spammy block does not displace clean incumbent",
       best({&CleanInc,&SpamLate})->name == "clean_incumbent");

    // ---- strict weak ordering, exhaustively over a small population
    std::vector<Idx> pop;
    for (uint64_t w : {100ull, 101ull})
        for (int32_t s : {1, 2})
            for (uint32_t sp : {0u, 7u, LATE})
                pop.push_back(Idx{w, s, sp, ""});
    std::vector<Idx*> p; for (auto& i : pop) p.push_back(&i);

    Cmp c;
    bool irreflexive = true, asym = true, trans = true, trans_eq = true;
    for (auto a : p) {
        if (c(a,a)) irreflexive = false;
        for (auto b : p) {
            if (c(a,b) && c(b,a)) asym = false;
            for (auto d : p) {
                if (c(a,b) && c(b,d) && !c(a,d)) trans = false;
                bool eab = !c(a,b) && !c(b,a);
                bool ebd = !c(b,d) && !c(d,b);
                bool ead = !c(a,d) && !c(d,a);
                if (eab && ebd && !ead) trans_eq = false;
            }
        }
    }
    ck("irreflexive", irreflexive);
    ck("asymmetric", asym);
    ck("transitive", trans);
    ck("transitivity of equivalence", trans_eq);

    // ---- disabled must be byte-identical in behaviour to unpatched
    bool identical = true;
    for (auto a : p) for (auto b : p) {
        g_spam_tiebreak = true;  bool on  = c(a,b);
        g_spam_tiebreak = false; bool off = c(a,b);
        if (a->m_spam_score == b->m_spam_score && on != off) identical = false;
    }
    ck("enabling changes nothing when spam scores are equal", identical);

    std::cout << "\n" << (failures ? "FAILURES: " + std::to_string(failures)
                                   : "all passed") << "\n";
    return failures ? 1 : 0;
}
