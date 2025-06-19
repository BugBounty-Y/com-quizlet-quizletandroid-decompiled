package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = q.class)
/* loaded from: classes3.dex */
public final class r implements serialization.b {

    @NotNull
    public static final TaskProgressBucketType$Companion Companion;
    public static final r b;
    public static final /* synthetic */ r[] c;
    public final int a;

    static {
        r rVar = new r("CORRECT", 0, 0);
        b = rVar;
        r[] rVarArr = {rVar, new r("INCORRECT", 1, 1), new r("UNANSWERED", 2, 2)};
        c = rVarArr;
        AbstractC3328d.f(rVarArr);
        Companion = new TaskProgressBucketType$Companion();
    }

    public r(String str, int i, int i2) {
        this.a = i2;
    }

    public static r valueOf(String str) {
        return (r) Enum.valueOf(r.class, str);
    }

    public static r[] values() {
        return (r[]) c.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
