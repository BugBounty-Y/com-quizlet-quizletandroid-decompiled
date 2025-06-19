package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = m.class)
/* loaded from: classes3.dex */
public final class n implements serialization.f {

    @NotNull
    public static final SrsStatus$Companion Companion;
    public static final /* synthetic */ n[] b;
    public final String a;

    static {
        n[] nVarArr = {new n("DUE", 0, "Due"), new n("NOT_DUE", 1, "Not due"), new n("NOT_STUDIED", 2, "Not studied")};
        b = nVarArr;
        AbstractC3328d.f(nVarArr);
        Companion = new SrsStatus$Companion();
    }

    public n(String str, int i, String str2) {
        this.a = str2;
    }

    public static n valueOf(String str) {
        return (n) Enum.valueOf(n.class, str);
    }

    public static n[] values() {
        return (n[]) b.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
