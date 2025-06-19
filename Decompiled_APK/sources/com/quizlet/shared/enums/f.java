package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = e.class)
/* loaded from: classes3.dex */
public final class f implements serialization.f {

    @NotNull
    public static final MemoryScoreLabel$Companion Companion;
    public static final /* synthetic */ f[] b;
    public final String a;

    static {
        f[] fVarArr = {new f("DAY", 0, "Day"), new f("WEEK", 1, "Week"), new f("MONTH", 2, "Month")};
        b = fVarArr;
        AbstractC3328d.f(fVarArr);
        Companion = new MemoryScoreLabel$Companion();
    }

    public f(String str, int i, String str2) {
        this.a = str2;
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) b.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
