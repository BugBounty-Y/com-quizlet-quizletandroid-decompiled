package com.pubmatic.sdk.video.renderer;

import com.pubmatic.sdk.video.vastmodels.l;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class b {
    static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[l.b.values().length];
        a = iArr;
        try {
            iArr[l.b.FIRST_QUARTILE.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[l.b.MID_POINT.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            a[l.b.THIRD_QUARTILE.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            a[l.b.COMPLETE.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            a[l.b.UNMUTE.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            a[l.b.MUTE.ordinal()] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            a[l.b.SKIP.ordinal()] = 7;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            a[l.b.RESUME.ordinal()] = 8;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            a[l.b.PAUSE.ordinal()] = 9;
        } catch (NoSuchFieldError unused9) {
        }
    }
}
