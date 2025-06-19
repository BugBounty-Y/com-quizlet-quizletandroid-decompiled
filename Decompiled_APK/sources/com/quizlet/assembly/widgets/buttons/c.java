package com.quizlet.assembly.widgets.buttons;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final c e;
    public static final /* synthetic */ c[] f;
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    static {
        c cVar = new c("SMALL", 0, R.dimen.assembly_button_padding_horizontal_small, R.dimen.assembly_button_padding_vertical_small, R.dimen.assembly_button_line_height_small, R.dimen.ref_size_small);
        c cVar2 = new c("MEDIUM", 1, R.dimen.assembly_button_padding_horizontal_medium, R.dimen.assembly_button_padding_vertical_medium, R.dimen.assembly_button_line_height_medium, R.dimen.ref_size_small);
        c cVar3 = new c("LARGE", 2, R.dimen.assembly_button_padding_horizontal_large, R.dimen.assembly_button_padding_vertical_large, R.dimen.assembly_button_line_height_large, R.dimen.ref_size_small);
        e = cVar3;
        c[] cVarArr = {cVar, cVar2, cVar3, new c("XLARGE", 3, R.dimen.assembly_button_padding_horizontal_xlarge, R.dimen.assembly_button_padding_vertical_xlarge, R.dimen.assembly_button_line_height_xlarge, R.dimen.ref_size_medium)};
        f = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public c(String str, int i, int i2, int i3, int i4, int i5) {
        this.a = i2;
        this.b = i3;
        this.c = i4;
        this.d = i5;
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) f.clone();
    }
}
