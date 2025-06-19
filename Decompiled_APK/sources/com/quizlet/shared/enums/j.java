package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f
/* loaded from: classes3.dex */
public final class j implements serialization.b {

    @NotNull
    public static final SelfIdentifiedUserType$Companion Companion;
    public static final Object b;
    public static final /* synthetic */ j[] c;
    public final int a;

    static {
        j[] jVarArr = {new j("UNKNOWN", 0, 0), new j("TEACHER", 1, 1), new j("STUDENT", 2, 2)};
        c = jVarArr;
        AbstractC3328d.f(jVarArr);
        Companion = new SelfIdentifiedUserType$Companion();
        b = kotlin.l.a(kotlin.m.b, i.b);
    }

    public j(String str, int i, int i2) {
        this.a = i2;
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) c.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
