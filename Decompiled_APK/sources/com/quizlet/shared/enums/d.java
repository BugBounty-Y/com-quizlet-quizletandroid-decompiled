package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = c.class)
/* loaded from: classes3.dex */
public final class d implements serialization.f {

    @NotNull
    public static final FlashcardOrdering$Companion Companion;
    public static final d b;
    public static final d c;
    public static final /* synthetic */ d[] d;
    public final String a;

    static {
        d dVar = new d("IN_ORDER", 0, "IN_ORDER");
        b = dVar;
        d dVar2 = new d("SHUFFLED", 1, "SHUFFLED");
        c = dVar2;
        d[] dVarArr = {dVar, dVar2};
        d = dVarArr;
        AbstractC3328d.f(dVarArr);
        Companion = new FlashcardOrdering$Companion();
    }

    public d(String str, int i, String str2) {
        this.a = str2;
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) d.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
