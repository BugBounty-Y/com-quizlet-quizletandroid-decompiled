package com.appsflyer.internal;

import java.util.ArrayList;
import kotlin.C4937f;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.D;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFd1qSDK {

    @Metadata
    /* renamed from: com.appsflyer.internal.AFd1qSDK$5, reason: invalid class name */
    public static final class AnonymousClass5 extends r implements Function1<StackTraceElement, CharSequence> {
        public static final AnonymousClass5 getMediationNetwork = new AnonymousClass5();

        public AnonymousClass5() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        @NotNull
        /* renamed from: AFAdRevenueData, reason: merged with bridge method [inline-methods] */
        public final CharSequence invoke(@NotNull StackTraceElement stackTraceElement) {
            Intrinsics.checkNotNullParameter(stackTraceElement, "");
            return "at " + stackTraceElement;
        }
    }

    @NotNull
    public static final AFc1cSDK getCurrencyIso4217Code(@NotNull Throwable th, @NotNull String str) {
        Intrinsics.checkNotNullParameter(th, "");
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(th, "");
        String name = th.getClass().getName();
        Intrinsics.checkNotNullExpressionValue(name, "");
        return new AFc1cSDK(android.support.v4.media.session.a.l(name, ": ", str), getMediationNetwork(th), C4937f.b(th), 0, 8, null);
    }

    @NotNull
    private static String getMediationNetwork(@NotNull Throwable th) {
        Intrinsics.checkNotNullParameter(th, "");
        Intrinsics.checkNotNullParameter(th, "");
        Intrinsics.checkNotNullParameter(th, "");
        StackTraceElement[] stackTrace = th.getStackTrace();
        Intrinsics.checkNotNullExpressionValue(stackTrace, "");
        ArrayList arrayList = new ArrayList();
        for (StackTraceElement stackTraceElement : stackTrace) {
            String className = stackTraceElement.getClassName();
            Intrinsics.checkNotNullExpressionValue(className, "");
            if (!D.r(className, "com.appsflyer", false)) {
                stackTraceElement = null;
            }
            if (stackTraceElement != null) {
                arrayList.add(stackTraceElement);
            }
        }
        String str = th + "\n" + CollectionsKt.S(arrayList, "\n", null, null, AnonymousClass5.getMediationNetwork, 30);
        Intrinsics.checkNotNullParameter(str, "");
        return AFd1rSDK.getCurrencyIso4217Code(str, "SHA-256");
    }
}
