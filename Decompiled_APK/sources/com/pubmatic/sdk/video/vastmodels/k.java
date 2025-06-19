package com.pubmatic.sdk.video.vastmodels;

import com.pubmatic.sdk.video.vastmodels.j;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class k {
    static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[j.a.values().length];
        a = iArr;
        try {
            iArr[j.a.CLICK_THROUGH.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[j.a.ICON.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            a[j.a.IMPRESSIONS.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            a[j.a.ERRORS.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            a[j.a.VIEWABLE_IMPRESSIONS.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            a[j.a.NOT_VIEWABLE_IMPRESSIONS.ordinal()] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            a[j.a.VIEW_UNDETERMINED_IMPRESSIONS.ordinal()] = 7;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            a[j.a.CLICKTRACKING.ordinal()] = 8;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            a[j.a.PROGRESS_TRACKING_EVENT.ordinal()] = 9;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            a[j.a.COMPANIONS.ordinal()] = 10;
        } catch (NoSuchFieldError unused10) {
        }
    }
}
