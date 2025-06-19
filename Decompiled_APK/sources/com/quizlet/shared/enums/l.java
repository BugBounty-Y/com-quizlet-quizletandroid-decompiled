package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = k.class)
/* loaded from: classes3.dex */
public final class l implements serialization.f {

    @NotNull
    public static final SmartTextGradingGrade$Companion Companion;
    public static final l b;
    public static final /* synthetic */ l[] c;
    public final String a;

    static {
        l lVar = new l("CORRECT", 0, "correct");
        b = lVar;
        l[] lVarArr = {lVar, new l("CLOSE", 1, "close"), new l("PARTIAL", 2, "partial"), new l("WRONG", 3, "wrong")};
        c = lVarArr;
        AbstractC3328d.f(lVarArr);
        Companion = new SmartTextGradingGrade$Companion();
    }

    public l(String str, int i, String str2) {
        this.a = str2;
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) c.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
