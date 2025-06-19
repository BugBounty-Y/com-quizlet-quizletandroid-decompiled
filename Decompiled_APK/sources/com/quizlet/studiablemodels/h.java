package com.quizlet.studiablemodels;

import assistantMode.enums.StudiableCardSideLabel$Companion;
import assistantMode.enums.m;
import com.quizlet.generated.enums.O1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class h {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[O1.values().length];
        try {
            iArr[O1.WORD.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[O1.DEFINITION.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[O1.LOCATION.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        a = iArr;
        int[] iArr2 = new int[m.values().length];
        try {
            iArr2[0] = 1;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            StudiableCardSideLabel$Companion studiableCardSideLabel$Companion = m.Companion;
            iArr2[1] = 2;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            StudiableCardSideLabel$Companion studiableCardSideLabel$Companion2 = m.Companion;
            iArr2[2] = 3;
        } catch (NoSuchFieldError unused6) {
        }
    }
}
