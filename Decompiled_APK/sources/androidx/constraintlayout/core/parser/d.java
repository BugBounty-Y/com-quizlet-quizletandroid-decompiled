package androidx.constraintlayout.core.parser;

import java.util.ArrayList;
import java.util.Objects;

/* loaded from: classes.dex */
public final class d extends b {
    static {
        ArrayList arrayList = new ArrayList();
        arrayList.add("ConstraintSets");
        arrayList.add("Variables");
        arrayList.add("Generate");
        arrayList.add("Transitions");
        arrayList.add("KeyFrames");
        arrayList.add("KeyAttributes");
        arrayList.add("KeyPositions");
        arrayList.add("KeyCycles");
    }

    @Override // androidx.constraintlayout.core.parser.b, androidx.constraintlayout.core.parser.c
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d) || Objects.equals(c(), ((d) obj).c())) {
            return super.equals(obj);
        }
        return false;
    }
}
