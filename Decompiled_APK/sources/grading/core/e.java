package grading.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final grading.core.enums.b a;
    public final grading.core.enums.a b;

    public e(grading.core.enums.b actionEnum, grading.core.enums.a suggestedSettingEnum) {
        Intrinsics.checkNotNullParameter(actionEnum, "actionEnum");
        Intrinsics.checkNotNullParameter(suggestedSettingEnum, "suggestedSettingEnum");
        this.a = actionEnum;
        this.b = suggestedSettingEnum;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && this.b == eVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "GradingSettingsSuggestion(actionEnum=" + this.a + ", suggestedSettingEnum=" + this.b + ")";
    }
}
