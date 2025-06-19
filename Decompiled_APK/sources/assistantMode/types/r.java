package assistantMode.types;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class r extends t {
    public final assistantMode.enums.z a;

    public r(assistantMode.enums.z studySetting) {
        Intrinsics.checkNotNullParameter(studySetting, "studySetting");
        this.a = studySetting;
    }

    @Override // assistantMode.types.t
    public final assistantMode.enums.z a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof r) {
            return this.a == ((r) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "RecommendedConfigurationBoolean(studySetting=" + this.a + ", value=true)";
    }
}
