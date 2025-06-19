package com.quizlet.features.notes.helper;

import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.m2;
import com.quizlet.features.notes.data.b;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;

    static {
        int[] iArr = new int[b.values().length];
        try {
            iArr[0] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            b bVar = b.a;
            iArr[1] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
        int[] iArr2 = new int[EnumC4175w.values().length];
        try {
            iArr2[EnumC4175w.PENDING.ordinal()] = 1;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr2[EnumC4175w.MODERATION.ordinal()] = 2;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr2[EnumC4175w.ERROR.ordinal()] = 3;
        } catch (NoSuchFieldError unused5) {
        }
        b = iArr2;
        int[] iArr3 = new int[m2.values().length];
        try {
            iArr3[0] = 1;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            m2 m2Var = m2.a;
            iArr3[1] = 2;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            m2 m2Var2 = m2.a;
            iArr3[2] = 3;
        } catch (NoSuchFieldError unused8) {
        }
    }
}
