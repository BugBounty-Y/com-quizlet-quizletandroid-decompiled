package com.quizlet.shared.enums.studynotes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = c.class)
/* loaded from: classes3.dex */
public final class d implements serialization.b {

    @NotNull
    public static final StudyNotesArtifactStatus$Companion Companion;
    public static final d b;
    public static final d c;
    public static final /* synthetic */ d[] d;
    public final int a;

    static {
        d dVar = new d("PENDING", 0, 0);
        b = dVar;
        d dVar2 = new d("COMPLETE", 1, 1);
        c = dVar2;
        d[] dVarArr = {dVar, dVar2, new d("ERROR", 2, 2), new d("MODERATION", 3, 3)};
        d = dVarArr;
        AbstractC3328d.f(dVarArr);
        Companion = new StudyNotesArtifactStatus$Companion();
    }

    public d(String str, int i, int i2) {
        this.a = i2;
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) d.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
