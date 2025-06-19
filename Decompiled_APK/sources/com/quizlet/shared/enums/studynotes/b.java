package com.quizlet.shared.enums.studynotes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = a.class)
/* loaded from: classes3.dex */
public final class b implements serialization.f {

    @NotNull
    public static final EssayDifficulty$Companion Companion;
    public static final /* synthetic */ b[] b;
    public final String a;

    static {
        b[] bVarArr = {new b("EASY", 0, "easy"), new b("MEDIUM", 1, "medium"), new b("HARD", 2, "hard")};
        b = bVarArr;
        AbstractC3328d.f(bVarArr);
        Companion = new EssayDifficulty$Companion();
    }

    public b(String str, int i, String str2) {
        this.a = str2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) b.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
