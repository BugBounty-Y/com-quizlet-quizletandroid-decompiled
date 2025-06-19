package com.quizlet.ads;

import com.comscore.streaming.EventType;
import com.google.android.gms.ads.h;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.collections.B;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final com.google.mlkit.common.sdkinternal.model.a b;
    public static final c c;
    public static final c d;
    public static final c e;
    public static final c f;
    public static final c g;
    public static final c h;
    public static final /* synthetic */ c[] i;
    public final int a;

    static {
        c cVar = new c("AndroidHome320x50", 0, R.string.home_ad_unit_AndroidHome320x50);
        c cVar2 = new c("AndroidTabletHomeFooter", 1, R.string.home_ad_unit_AndroidTabletHomeFooter);
        c cVar3 = new c("AndroidAllSetsFooter320x50", 2, R.string.home_ad_unit_AndroidAllSetsFooter320x50);
        c cVar4 = new c("AndroidSet320x50", 3, R.string.setpage_ad_unit_AndroidSet320x50);
        c cVar5 = new c("AndroidSetFooter320x50", 4, R.string.setpage_ad_unit_AndroidSetFooter320x50);
        c cVar6 = new c("AndroidTabletSetFooterFlexi", 5, R.string.setpage_ad_unit_AndroidTabletSetFooterFlexi);
        c cVar7 = new c("AndroidSetSqr", 6, R.string.setpage_ad_unit_AndroidSetSqr);
        c cVar8 = new c("AndroidSetSqr2", 7, R.string.setpage_ad_unit_AndroidSetSqr2);
        c cVar9 = new c("AndroidSetSqr3", 8, R.string.setpage_ad_unit_AndroidSetSqr3);
        c cVar10 = new c("AndroidSetSqr4", 9, R.string.setpage_ad_unit_AndroidSetSqr4);
        c cVar11 = new c("AndroidSetSqr5", 10, R.string.setpage_ad_unit_AndroidSetSqr5);
        c cVar12 = new c("AndroidSetSqr6", 11, R.string.setpage_ad_unit_AndroidSetSqr6);
        c cVar13 = new c("AndroidSetSqr7", 12, R.string.setpage_ad_unit_AndroidSetSqr7);
        c cVar14 = new c("AndroidSetSqr8", 13, R.string.setpage_ad_unit_AndroidSetSqr8);
        c cVar15 = new c("AndroidSetSqr9", 14, R.string.setpage_ad_unit_AndroidSetSqr9);
        c cVar16 = new c("AndroidSetSqr10", 15, R.string.setpage_ad_unit_AndroidSetSqr10);
        c cVar17 = new c("AndroidSearchSqr", 16, R.string.search_ad_unit_AndroidSearchSqr);
        c = cVar17;
        c cVar18 = new c("AndroidSearchSqr2", 17, R.string.search_ad_unit_AndroidSearchSqr2);
        d = cVar18;
        c cVar19 = new c("AndroidSearchSqr3", 18, R.string.search_ad_unit_AndroidSearchSqr3);
        e = cVar19;
        c cVar20 = new c("AndroidSearchSqr4", 19, R.string.search_ad_unit_AndroidSearchSqr4);
        f = cVar20;
        c cVar21 = new c("AndroidSearchSqr5", 20, R.string.search_ad_unit_AndroidSearchSqr5);
        g = cVar21;
        c cVar22 = new c("AndroidInterstitialLearnModeCheckpoint", 21, R.string.learn_mode_ad_unit_AndroidInterstitialLearnModeCheckpoint);
        h = cVar22;
        c[] cVarArr = {cVar, cVar2, cVar3, cVar4, cVar5, cVar6, cVar7, cVar8, cVar9, cVar10, cVar11, cVar12, cVar13, cVar14, cVar15, cVar16, cVar17, cVar18, cVar19, cVar20, cVar21, cVar22, new c("AndroidMatch320x50", 22, R.string.match_mode_ad_unit_AndroidMatch320x50)};
        i = cVarArr;
        AbstractC3328d.f(cVarArr);
        b = new com.google.mlkit.common.sdkinternal.model.a(23);
    }

    public c(String str, int i2, int i3) {
        this.a = i3;
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) i.clone();
    }

    public final List a(boolean z) {
        switch (ordinal()) {
            case 0:
                return A.b(h.i);
            case 1:
                return B.j(h.i, h.l);
            case 2:
                return A.b(h.i);
            case 3:
                return A.b(h.i);
            case 4:
                return A.b(h.i);
            case 5:
                return B.j(h.i, h.j, h.l);
            case 6:
                ArrayList arrayListK = B.k(h.p, h.m, h.i);
                if (z) {
                    arrayListK.add(new h(640, 360));
                }
                return arrayListK;
            case 7:
                return B.j(h.i, h.m);
            case 8:
                return B.j(h.i, h.m);
            case 9:
                return B.j(h.i, h.m);
            case 10:
                return B.j(h.i, h.m);
            case 11:
                return B.j(h.i, h.m);
            case 12:
                return B.j(h.i, h.m);
            case 13:
                return B.j(h.i, h.m);
            case 14:
                return B.j(h.i, h.m);
            case 15:
                return B.j(h.i, h.m);
            case 16:
                return B.j(h.i, h.m);
            case 17:
                return B.j(h.i, h.m);
            case 18:
                return B.j(h.i, h.m);
            case 19:
                return B.j(h.i, h.m);
            case 20:
                return B.j(h.i, h.m);
            case 21:
                ArrayList arrayListK2 = B.k(h.p, h.m);
                if (z) {
                    arrayListK2.add(new h(300, com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR));
                    arrayListK2.add(new h(640, 360));
                }
                return arrayListK2;
            case EventType.WINDOW_STATE /* 22 */:
                return A.b(h.i);
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public final boolean b() {
        switch (ordinal()) {
            case 0:
            case 1:
            case 2:
                return true;
            case 3:
                return false;
            case 4:
            case 5:
                return true;
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case EventType.WINDOW_STATE /* 22 */:
                return false;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
