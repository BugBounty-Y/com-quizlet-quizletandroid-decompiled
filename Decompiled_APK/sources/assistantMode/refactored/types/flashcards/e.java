package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final ArrayList a;
    public final ArrayList b;
    public final ArrayList c;
    public final int d;
    public final kotlin.random.g e;

    public e(ArrayList itemIdsStudiedInCurrentCycle, ArrayList itemIdsRemainingInCurrentCycle, ArrayList itemIdsInNextCycle, int i, kotlin.random.g random) {
        Intrinsics.checkNotNullParameter(itemIdsStudiedInCurrentCycle, "itemIdsStudiedInCurrentCycle");
        Intrinsics.checkNotNullParameter(itemIdsRemainingInCurrentCycle, "itemIdsRemainingInCurrentCycle");
        Intrinsics.checkNotNullParameter(itemIdsInNextCycle, "itemIdsInNextCycle");
        Intrinsics.checkNotNullParameter(random, "random");
        this.a = itemIdsStudiedInCurrentCycle;
        this.b = itemIdsRemainingInCurrentCycle;
        this.c = itemIdsInNextCycle;
        this.d = i;
        this.e = random;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a.equals(eVar.a) && this.b.equals(eVar.b) && this.c.equals(eVar.c) && this.d == eVar.d && this.e.equals(eVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.b(this.d, d0.h(this.c, d0.h(this.b, this.a.hashCode() * 31, 31), 31), 31);
    }

    public final String toString() {
        return "FlashcardsOrderedInitialState(itemIdsStudiedInCurrentCycle=" + this.a + ", itemIdsRemainingInCurrentCycle=" + this.b + ", itemIdsInNextCycle=" + this.c + ", round=" + this.d + ", random=" + this.e + ")";
    }
}
