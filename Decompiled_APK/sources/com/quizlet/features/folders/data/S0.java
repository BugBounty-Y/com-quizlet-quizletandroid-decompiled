package com.quizlet.features.folders.data;

/* loaded from: classes3.dex */
public final class S0 {
    public final boolean a;
    public final boolean b;

    public S0(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof S0)) {
            return false;
        }
        S0 s0 = (S0) obj;
        return this.a == s0.a && this.b == s0.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StudyButtonEligibility(isStudyFolderFeatureEnabled=" + this.a + ", isLearnEnabled=" + this.b + ")";
    }
}
