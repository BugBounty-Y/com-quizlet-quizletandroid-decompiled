package com.pubmatic.sdk.omsdk;

import com.pubmatic.sdk.common.viewability.l;
import com.pubmatic.sdk.common.viewability.m;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class e {
    static final /* synthetic */ int[] a;
    static final /* synthetic */ int[] b;
    static final /* synthetic */ int[] c;

    static {
        int[] iArr = new int[l.values().length];
        c = iArr;
        try {
            iArr[l.GENERIC.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            c[l.VIDEO.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        int[] iArr2 = new int[m.values().length];
        b = iArr2;
        try {
            iArr2[m.FULLSCREEN.ordinal()] = 1;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            b[m.COLLAPSED.ordinal()] = 2;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            b[m.EXPANDED.ordinal()] = 3;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            b[m.MINIMIZED.ordinal()] = 4;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            b[m.NORMAL.ordinal()] = 5;
        } catch (NoSuchFieldError unused7) {
        }
        int[] iArr3 = new int[com.pubmatic.sdk.common.g.values().length];
        a = iArr3;
        try {
            iArr3[com.pubmatic.sdk.common.g.FIRST_QUARTILE.ordinal()] = 1;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            a[com.pubmatic.sdk.common.g.MID_POINT.ordinal()] = 2;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            a[com.pubmatic.sdk.common.g.THIRD_QUARTILE.ordinal()] = 3;
        } catch (NoSuchFieldError unused10) {
        }
        try {
            a[com.pubmatic.sdk.common.g.COMPLETE.ordinal()] = 4;
        } catch (NoSuchFieldError unused11) {
        }
        try {
            a[com.pubmatic.sdk.common.g.SKIPPED.ordinal()] = 5;
        } catch (NoSuchFieldError unused12) {
        }
        try {
            a[com.pubmatic.sdk.common.g.MUTE.ordinal()] = 6;
        } catch (NoSuchFieldError unused13) {
        }
        try {
            a[com.pubmatic.sdk.common.g.UNMUTE.ordinal()] = 7;
        } catch (NoSuchFieldError unused14) {
        }
        try {
            a[com.pubmatic.sdk.common.g.CLICKED.ordinal()] = 8;
        } catch (NoSuchFieldError unused15) {
        }
        try {
            a[com.pubmatic.sdk.common.g.PAUSE.ordinal()] = 9;
        } catch (NoSuchFieldError unused16) {
        }
        try {
            a[com.pubmatic.sdk.common.g.RESUME.ordinal()] = 10;
        } catch (NoSuchFieldError unused17) {
        }
        try {
            a[com.pubmatic.sdk.common.g.ICON_CLICKED.ordinal()] = 11;
        } catch (NoSuchFieldError unused18) {
        }
    }
}
