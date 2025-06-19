package assistantMode.types;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class s extends t {
    public final assistantMode.enums.z a;
    public final int b;

    public s(assistantMode.enums.z studySetting, int i) {
        Intrinsics.checkNotNullParameter(studySetting, "studySetting");
        this.a = studySetting;
        this.b = i;
    }

    @Override // assistantMode.types.t
    public final assistantMode.enums.z a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return this.a == sVar.a && this.b == sVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "RecommendedConfigurationInt(studySetting=" + this.a + ", value=" + this.b + ")";
    }
}
