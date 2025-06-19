package com.quizlet.search.paging;

import androidx.paging.P0;
import androidx.paging.S0;
import androidx.paging.T0;
import com.quizlet.data.repository.achievements.h;
import com.quizlet.search.viewmodels.AbstractC4797c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends S0 {
    public final /* synthetic */ int b = 0;
    public final String c;
    public final h d;
    public final AbstractC4797c e;
    public final int f;
    public String g;
    public final Object h;

    public b(com.google.mlkit.vision.documentscanner.internal.c searchClassUseCase, String query, h searchAdsManager, AbstractC4797c onSearchPageLoadedListener) {
        Intrinsics.checkNotNullParameter(searchClassUseCase, "searchClassUseCase");
        Intrinsics.checkNotNullParameter(query, "query");
        Intrinsics.checkNotNullParameter(searchAdsManager, "searchAdsManager");
        Intrinsics.checkNotNullParameter(onSearchPageLoadedListener, "onSearchPageLoadedListener");
        this.h = searchClassUseCase;
        this.c = query;
        this.d = searchAdsManager;
        this.e = onSearchPageLoadedListener;
        this.f = 20;
    }

    @Override // androidx.paging.S0
    public final Integer a(T0 state) {
        Integer num;
        Integer num2;
        Integer num3;
        Integer num4;
        switch (this.b) {
            case 0:
                Intrinsics.checkNotNullParameter(state, "state");
                Integer num5 = state.b;
                if (num5 != null) {
                    int iIntValue = num5.intValue();
                    P0 p0A = state.a(iIntValue);
                    if (p0A != null && (num2 = p0A.b) != null) {
                        return Integer.valueOf(num2.intValue() + 1);
                    }
                    P0 p0A2 = state.a(iIntValue);
                    if (p0A2 != null && (num = p0A2.c) != null) {
                        return Integer.valueOf(num.intValue() - 1);
                    }
                }
                return null;
            default:
                Intrinsics.checkNotNullParameter(state, "state");
                Integer num6 = state.b;
                if (num6 != null) {
                    int iIntValue2 = num6.intValue();
                    P0 p0A3 = state.a(iIntValue2);
                    if (p0A3 != null && (num4 = p0A3.b) != null) {
                        return Integer.valueOf(num4.intValue() + 1);
                    }
                    P0 p0A4 = state.a(iIntValue2);
                    if (p0A4 != null && (num3 = p0A4.c) != null) {
                        return Integer.valueOf(num3.intValue() - 1);
                    }
                }
                return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x01d8  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x01da A[Catch: Exception -> 0x0135, TryCatch #1 {Exception -> 0x0135, blocks: (B:70:0x0130, B:100:0x01c7, B:104:0x01e1, B:108:0x01f2, B:107:0x01ec, B:103:0x01da, B:77:0x0145, B:88:0x017d, B:90:0x0183, B:92:0x0187, B:93:0x019f, B:95:0x01a5, B:96:0x01b4, B:80:0x014c, B:82:0x0154, B:84:0x015a), top: B:114:0x0124 }] */
    /* JADX WARN: Removed duplicated region for block: B:106:0x01eb  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x01ec A[Catch: Exception -> 0x0135, TryCatch #1 {Exception -> 0x0135, blocks: (B:70:0x0130, B:100:0x01c7, B:104:0x01e1, B:108:0x01f2, B:107:0x01ec, B:103:0x01da, B:77:0x0145, B:88:0x017d, B:90:0x0183, B:92:0x0187, B:93:0x019f, B:95:0x01a5, B:96:0x01b4, B:80:0x014c, B:82:0x0154, B:84:0x015a), top: B:114:0x0124 }] */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0019  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00de A[Catch: Exception -> 0x0039, TryCatch #0 {Exception -> 0x0039, blocks: (B:16:0x0034, B:46:0x00cb, B:50:0x00e5, B:54:0x00f6, B:53:0x00f0, B:49:0x00de, B:23:0x0049, B:34:0x0081, B:36:0x0087, B:38:0x008b, B:39:0x00a3, B:41:0x00a9, B:42:0x00b8, B:26:0x0050, B:28:0x0058, B:30:0x005e), top: B:112:0x0028 }] */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00f0 A[Catch: Exception -> 0x0039, TryCatch #0 {Exception -> 0x0039, blocks: (B:16:0x0034, B:46:0x00cb, B:50:0x00e5, B:54:0x00f6, B:53:0x00f0, B:49:0x00de, B:23:0x0049, B:34:0x0081, B:36:0x0087, B:38:0x008b, B:39:0x00a3, B:41:0x00a9, B:42:0x00b8, B:26:0x0050, B:28:0x0058, B:30:0x005e), top: B:112:0x0028 }] */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0115  */
    /* JADX WARN: Type inference failed for: r0v23, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v9, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r2v16, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Iterable, java.lang.Object] */
    @Override // androidx.paging.S0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(androidx.paging.N0 r11, kotlin.coroutines.jvm.internal.c r12) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 516
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.search.paging.b.c(androidx.paging.N0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public b(com.quizlet.data.interactor.achievements.f searchUserUseCase, String query, h searchAdsManager, AbstractC4797c onSearchPageLoadedListener) {
        Intrinsics.checkNotNullParameter(searchUserUseCase, "searchUserUseCase");
        Intrinsics.checkNotNullParameter(query, "query");
        Intrinsics.checkNotNullParameter(searchAdsManager, "searchAdsManager");
        Intrinsics.checkNotNullParameter(onSearchPageLoadedListener, "onSearchPageLoadedListener");
        this.h = searchUserUseCase;
        this.c = query;
        this.d = searchAdsManager;
        this.e = onSearchPageLoadedListener;
        this.f = 25;
    }
}
