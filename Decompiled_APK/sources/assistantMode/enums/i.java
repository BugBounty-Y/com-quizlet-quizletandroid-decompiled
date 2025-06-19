package assistantMode.enums;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i {
    public final h a;
    public final String b;

    public i(h optionGenerationSourceEnum, String optionGenerationSourceStrVal) {
        Intrinsics.checkNotNullParameter(optionGenerationSourceEnum, "optionGenerationSourceEnum");
        Intrinsics.checkNotNullParameter(optionGenerationSourceStrVal, "optionGenerationSourceStrVal");
        this.a = optionGenerationSourceEnum;
        this.b = optionGenerationSourceStrVal;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && Intrinsics.b(this.b, iVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "OptionGenerationSourcePair(optionGenerationSourceEnum=" + this.a + ", optionGenerationSourceStrVal=" + this.b + ")";
    }
}
