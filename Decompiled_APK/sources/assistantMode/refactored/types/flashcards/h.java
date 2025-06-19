package assistantMode.refactored.types.flashcards;

import java.util.HashSet;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public final Object a;
    public final HashSet b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final int f;

    public h(Set itemIdsStudiedInCurrentCycle, HashSet itemIdsRemainingInCurrentCycle, Set itemIdsMarkedAsUnknownInCurrentCycle, Set itemIdsMarkedAsKnownOrSkippedInCurrentCycle, Set itemIdsStudiedInCurrentRound, int i) {
        Intrinsics.checkNotNullParameter(itemIdsStudiedInCurrentCycle, "itemIdsStudiedInCurrentCycle");
        Intrinsics.checkNotNullParameter(itemIdsRemainingInCurrentCycle, "itemIdsRemainingInCurrentCycle");
        Intrinsics.checkNotNullParameter(itemIdsMarkedAsUnknownInCurrentCycle, "itemIdsMarkedAsUnknownInCurrentCycle");
        Intrinsics.checkNotNullParameter(itemIdsMarkedAsKnownOrSkippedInCurrentCycle, "itemIdsMarkedAsKnownOrSkippedInCurrentCycle");
        Intrinsics.checkNotNullParameter(itemIdsStudiedInCurrentRound, "itemIdsStudiedInCurrentRound");
        this.a = itemIdsStudiedInCurrentCycle;
        this.b = itemIdsRemainingInCurrentCycle;
        this.c = itemIdsMarkedAsUnknownInCurrentCycle;
        this.d = itemIdsMarkedAsKnownOrSkippedInCurrentCycle;
        this.e = itemIdsStudiedInCurrentRound;
        this.f = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && this.b.equals(hVar.b) && Intrinsics.b(this.c, hVar.c) && Intrinsics.b(this.d, hVar.d) && Intrinsics.b(this.e, hVar.e) && this.f == hVar.f;
    }

    public final int hashCode() {
        return Integer.hashCode(this.f) + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsUnorderedInitialState(itemIdsStudiedInCurrentCycle=");
        sb.append(this.a);
        sb.append(", itemIdsRemainingInCurrentCycle=");
        sb.append(this.b);
        sb.append(", itemIdsMarkedAsUnknownInCurrentCycle=");
        sb.append(this.c);
        sb.append(", itemIdsMarkedAsKnownOrSkippedInCurrentCycle=");
        sb.append(this.d);
        sb.append(", itemIdsStudiedInCurrentRound=");
        sb.append(this.e);
        sb.append(", round=");
        return android.support.v4.media.session.a.r(sb, this.f, ")");
    }
}
