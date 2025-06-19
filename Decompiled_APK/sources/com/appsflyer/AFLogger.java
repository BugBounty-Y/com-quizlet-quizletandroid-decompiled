package com.appsflyer;

import com.appsflyer.internal.AFg1cSDK;
import com.appsflyer.internal.AFg1gSDK;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.G;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.k;
import kotlin.l;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFLogger extends AFg1gSDK {

    @NotNull
    public static final AFLogger INSTANCE = new AFLogger();

    @NotNull
    private static final k getMediationNetwork = l.b(AnonymousClass8.getMediationNetwork);

    @NotNull
    private static final k getRevenue = l.b(AnonymousClass3.getMediationNetwork);

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$1, reason: invalid class name */
    public static final class AnonymousClass1 extends r implements Function1<AFg1gSDK, Unit> {
        private /* synthetic */ String $getCurrencyIso4217Code;
        private /* synthetic */ AFg1cSDK $getMediationNetwork;
        private /* synthetic */ boolean $getRevenue;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass1(AFg1cSDK aFg1cSDK, String str, boolean z) {
            super(1);
            this.$getMediationNetwork = aFg1cSDK;
            this.$getCurrencyIso4217Code = str;
            this.$getRevenue = z;
        }

        public final void getRevenue(@NotNull AFg1gSDK aFg1gSDK) {
            Intrinsics.checkNotNullParameter(aFg1gSDK, "");
            aFg1gSDK.d(this.$getMediationNetwork, this.$getCurrencyIso4217Code, this.$getRevenue);
        }

        @Override // kotlin.jvm.functions.Function1
        public final /* synthetic */ Object invoke(Object obj) {
            getRevenue((AFg1gSDK) obj);
            return Unit.a;
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$2, reason: invalid class name */
    public static final class AnonymousClass2 extends r implements Function1<AFg1gSDK, Unit> {
        private /* synthetic */ String $AFAdRevenueData;
        private /* synthetic */ boolean $areAllFieldsValid;
        private /* synthetic */ boolean $component2;
        private /* synthetic */ Throwable $getCurrencyIso4217Code;
        private /* synthetic */ AFg1cSDK $getMediationNetwork;
        private /* synthetic */ boolean $getMonetizationNetwork;
        private /* synthetic */ boolean $getRevenue;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass2(AFg1cSDK aFg1cSDK, String str, Throwable th, boolean z, boolean z2, boolean z3, boolean z4) {
            super(1);
            this.$getMediationNetwork = aFg1cSDK;
            this.$AFAdRevenueData = str;
            this.$getCurrencyIso4217Code = th;
            this.$getRevenue = z;
            this.$getMonetizationNetwork = z2;
            this.$areAllFieldsValid = z3;
            this.$component2 = z4;
        }

        public final void getRevenue(@NotNull AFg1gSDK aFg1gSDK) {
            Intrinsics.checkNotNullParameter(aFg1gSDK, "");
            aFg1gSDK.e(this.$getMediationNetwork, this.$AFAdRevenueData, this.$getCurrencyIso4217Code, this.$getRevenue, this.$getMonetizationNetwork, this.$areAllFieldsValid, this.$component2);
        }

        @Override // kotlin.jvm.functions.Function1
        public final /* synthetic */ Object invoke(Object obj) {
            getRevenue((AFg1gSDK) obj);
            return Unit.a;
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$3, reason: invalid class name */
    public static final class AnonymousClass3 extends r implements Function0<ExecutorService> {
        public static final AnonymousClass3 getMediationNetwork = new AnonymousClass3();

        public AnonymousClass3() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        /* renamed from: getMonetizationNetwork, reason: merged with bridge method [inline-methods] */
        public final ExecutorService invoke() {
            return Executors.newSingleThreadExecutor();
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$4, reason: invalid class name */
    public static final class AnonymousClass4 extends r implements Function1<AFg1gSDK, Unit> {
        private /* synthetic */ AFg1cSDK $getMediationNetwork;
        private /* synthetic */ String $getRevenue;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass4(AFg1cSDK aFg1cSDK, String str) {
            super(1);
            this.$getMediationNetwork = aFg1cSDK;
            this.$getRevenue = str;
        }

        public final void getMediationNetwork(@NotNull AFg1gSDK aFg1gSDK) {
            Intrinsics.checkNotNullParameter(aFg1gSDK, "");
            aFg1gSDK.force(this.$getMediationNetwork, this.$getRevenue);
        }

        @Override // kotlin.jvm.functions.Function1
        public final /* synthetic */ Object invoke(Object obj) {
            getMediationNetwork((AFg1gSDK) obj);
            return Unit.a;
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$5, reason: invalid class name */
    public static final class AnonymousClass5 extends r implements Function1<AFg1gSDK, Unit> {
        private /* synthetic */ AFg1cSDK $getCurrencyIso4217Code;
        private /* synthetic */ boolean $getMonetizationNetwork;
        private /* synthetic */ String $getRevenue;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass5(AFg1cSDK aFg1cSDK, String str, boolean z) {
            super(1);
            this.$getCurrencyIso4217Code = aFg1cSDK;
            this.$getRevenue = str;
            this.$getMonetizationNetwork = z;
        }

        public final void AFAdRevenueData(@NotNull AFg1gSDK aFg1gSDK) {
            Intrinsics.checkNotNullParameter(aFg1gSDK, "");
            aFg1gSDK.i(this.$getCurrencyIso4217Code, this.$getRevenue, this.$getMonetizationNetwork);
        }

        @Override // kotlin.jvm.functions.Function1
        public final /* synthetic */ Object invoke(Object obj) {
            AFAdRevenueData((AFg1gSDK) obj);
            return Unit.a;
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$6, reason: invalid class name */
    public static final class AnonymousClass6 extends r implements Function1<AFg1gSDK, Unit> {
        private /* synthetic */ AFg1cSDK $getMediationNetwork;
        private /* synthetic */ boolean $getMonetizationNetwork;
        private /* synthetic */ String $getRevenue;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass6(AFg1cSDK aFg1cSDK, String str, boolean z) {
            super(1);
            this.$getMediationNetwork = aFg1cSDK;
            this.$getRevenue = str;
            this.$getMonetizationNetwork = z;
        }

        public final void getMonetizationNetwork(@NotNull AFg1gSDK aFg1gSDK) {
            Intrinsics.checkNotNullParameter(aFg1gSDK, "");
            aFg1gSDK.v(this.$getMediationNetwork, this.$getRevenue, this.$getMonetizationNetwork);
        }

        @Override // kotlin.jvm.functions.Function1
        public final /* synthetic */ Object invoke(Object obj) {
            getMonetizationNetwork((AFg1gSDK) obj);
            return Unit.a;
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$8, reason: invalid class name */
    public static final class AnonymousClass8 extends r implements Function0<Set<AFg1gSDK>> {
        public static final AnonymousClass8 getMediationNetwork = new AnonymousClass8();

        public AnonymousClass8() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        /* renamed from: AFAdRevenueData, reason: merged with bridge method [inline-methods] */
        public final Set<AFg1gSDK> invoke() {
            return Collections.synchronizedSet(new LinkedHashSet());
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.AFLogger$9, reason: invalid class name */
    public static final class AnonymousClass9 extends r implements Function1<AFg1gSDK, Unit> {
        private /* synthetic */ boolean $AFAdRevenueData;
        private /* synthetic */ String $getMonetizationNetwork;
        private /* synthetic */ AFg1cSDK $getRevenue;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass9(AFg1cSDK aFg1cSDK, String str, boolean z) {
            super(1);
            this.$getRevenue = aFg1cSDK;
            this.$getMonetizationNetwork = str;
            this.$AFAdRevenueData = z;
        }

        public final void getCurrencyIso4217Code(@NotNull AFg1gSDK aFg1gSDK) {
            Intrinsics.checkNotNullParameter(aFg1gSDK, "");
            aFg1gSDK.w(this.$getRevenue, this.$getMonetizationNetwork, this.$AFAdRevenueData);
        }

        @Override // kotlin.jvm.functions.Function1
        public final /* synthetic */ Object invoke(Object obj) {
            getCurrencyIso4217Code((AFg1gSDK) obj);
            return Unit.a;
        }
    }

    @Metadata
    public enum LogLevel {
        NONE(0),
        ERROR(1),
        WARNING(2),
        INFO(3),
        DEBUG(4),
        VERBOSE(5);

        private final int level;

        LogLevel(int i) {
            this.level = i;
        }

        public final int getLevel() {
            return this.level;
        }
    }

    private AFLogger() {
    }

    @InterfaceC4935d
    public static final void afDebugLog(@NotNull String str, boolean z) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.d(AFg1cSDK.OTHER, str, z);
    }

    @InterfaceC4935d
    public static final void afErrorLog(@NotNull String str, @NotNull Throwable th, boolean z, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(th, "");
        AFg1gSDK.e$default(INSTANCE, AFg1cSDK.OTHER, str, th, z, z2, z3, false, 64, null);
    }

    @InterfaceC4935d
    public static final void afErrorLogForExcManagerOnly(String str, Throwable th) {
        AFLogger aFLogger = INSTANCE;
        AFg1cSDK aFg1cSDK = AFg1cSDK.OTHER;
        if (str == null || StringsKt.O(str)) {
            str = "null";
        }
        String str2 = str;
        if (th == null) {
            th = new NullPointerException("Invoked with null Throwable");
        }
        AFg1gSDK.e$default(aFLogger, aFg1cSDK, str2, th, false, false, true, false, 64, null);
    }

    @InterfaceC4935d
    public static final void afInfoLog(@NotNull String str, boolean z) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.i(AFg1cSDK.OTHER, str, z);
    }

    @InterfaceC4935d
    public static final void afLogForce(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.force(AFg1cSDK.OTHER, str);
    }

    @InterfaceC4935d
    public static final void afRDLog(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.v(AFg1cSDK.OTHER, str, true);
    }

    @InterfaceC4935d
    public static final void afVerboseLog(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.v(AFg1cSDK.OTHER, str, false);
    }

    @InterfaceC4935d
    public static final void afWarnLog(@NotNull String str, boolean z) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.w(AFg1cSDK.OTHER, str, z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void getCurrencyIso4217Code(AFg1gSDK[] aFg1gSDKArr) {
        Intrinsics.checkNotNullParameter(aFg1gSDKArr, "");
        k kVar = getMediationNetwork;
        Object value = kVar.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "");
        synchronized (((Set) value)) {
            Object value2 = kVar.getValue();
            Intrinsics.checkNotNullExpressionValue(value2, "");
            ((Set) value2).removeAll(C4933y.T(aFg1gSDKArr));
            Unit unit = Unit.a;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void getMediationNetwork(AFg1gSDK[] aFg1gSDKArr) {
        Intrinsics.checkNotNullParameter(aFg1gSDKArr, "");
        k kVar = getMediationNetwork;
        Object value = kVar.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "");
        synchronized (((Set) value)) {
            Object value2 = kVar.getValue();
            Intrinsics.checkNotNullExpressionValue(value2, "");
            G.v((Set) value2, aFg1gSDKArr);
            Unit unit = Unit.a;
        }
    }

    @Override // com.appsflyer.internal.AFg1gSDK
    public final void d(@NotNull AFg1cSDK aFg1cSDK, @NotNull String str, boolean z) {
        Intrinsics.checkNotNullParameter(aFg1cSDK, "");
        Intrinsics.checkNotNullParameter(str, "");
        ((ExecutorService) getRevenue.getValue()).execute(new a(0, new AnonymousClass1(aFg1cSDK, str, z)));
    }

    @Override // com.appsflyer.internal.AFg1gSDK
    public final void e(@NotNull AFg1cSDK aFg1cSDK, @NotNull String str, @NotNull Throwable th, boolean z, boolean z2, boolean z3, boolean z4) {
        Intrinsics.checkNotNullParameter(aFg1cSDK, "");
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(th, "");
        ((ExecutorService) getRevenue.getValue()).execute(new a(0, new AnonymousClass2(aFg1cSDK, str, th, z, z2, z3, z4)));
    }

    @Override // com.appsflyer.internal.AFg1gSDK
    public final void force(@NotNull AFg1cSDK aFg1cSDK, @NotNull String str) {
        Intrinsics.checkNotNullParameter(aFg1cSDK, "");
        Intrinsics.checkNotNullParameter(str, "");
        ((ExecutorService) getRevenue.getValue()).execute(new a(0, new AnonymousClass4(aFg1cSDK, str)));
    }

    @Override // com.appsflyer.internal.AFg1gSDK
    public final void i(@NotNull AFg1cSDK aFg1cSDK, @NotNull String str, boolean z) {
        Intrinsics.checkNotNullParameter(aFg1cSDK, "");
        Intrinsics.checkNotNullParameter(str, "");
        ((ExecutorService) getRevenue.getValue()).execute(new a(0, new AnonymousClass5(aFg1cSDK, str, z)));
    }

    public final void registerClient(@NotNull AFg1gSDK... aFg1gSDKArr) {
        Intrinsics.checkNotNullParameter(aFg1gSDKArr, "");
        ((ExecutorService) getRevenue.getValue()).execute(new b(aFg1gSDKArr, 0));
    }

    public final void unregisterClient(@NotNull AFg1gSDK... aFg1gSDKArr) {
        Intrinsics.checkNotNullParameter(aFg1gSDKArr, "");
        ((ExecutorService) getRevenue.getValue()).execute(new b(aFg1gSDKArr, 1));
    }

    @Override // com.appsflyer.internal.AFg1gSDK
    public final void v(@NotNull AFg1cSDK aFg1cSDK, @NotNull String str, boolean z) {
        Intrinsics.checkNotNullParameter(aFg1cSDK, "");
        Intrinsics.checkNotNullParameter(str, "");
        ((ExecutorService) getRevenue.getValue()).execute(new a(0, new AnonymousClass6(aFg1cSDK, str, z)));
    }

    @Override // com.appsflyer.internal.AFg1gSDK
    public final void w(@NotNull AFg1cSDK aFg1cSDK, @NotNull String str, boolean z) {
        Intrinsics.checkNotNullParameter(aFg1cSDK, "");
        Intrinsics.checkNotNullParameter(str, "");
        ((ExecutorService) getRevenue.getValue()).execute(new a(0, new AnonymousClass9(aFg1cSDK, str, z)));
    }

    @InterfaceC4935d
    public static final void afDebugLog(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.d(AFg1cSDK.OTHER, str, true);
    }

    @InterfaceC4935d
    public static final void afInfoLog(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        INSTANCE.i(AFg1cSDK.OTHER, str, true);
    }

    @InterfaceC4935d
    public static final void afWarnLog(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        AFg1gSDK.w$default(INSTANCE, AFg1cSDK.OTHER, str, false, 4, null);
    }

    @InterfaceC4935d
    public static final void afErrorLog(String str, Throwable th) {
        AFLogger aFLogger = INSTANCE;
        AFg1cSDK aFg1cSDK = AFg1cSDK.OTHER;
        if (str == null || StringsKt.O(str)) {
            str = "null";
        }
        String str2 = str;
        if (th == null) {
            th = new NullPointerException("Invoked with null Throwable");
        }
        AFg1gSDK.e$default(aFLogger, aFg1cSDK, str2, th, false, false, false, false, 120, null);
    }

    @InterfaceC4935d
    public static final void afErrorLogForExcManagerOnly(String str, Throwable th, boolean z) {
        AFLogger aFLogger = INSTANCE;
        AFg1cSDK aFg1cSDK = AFg1cSDK.OTHER;
        if (str == null || StringsKt.O(str)) {
            str = "null";
        }
        String str2 = str;
        if (th == null) {
            th = new NullPointerException("Invoked with null Throwable");
        }
        AFg1gSDK.e$default(aFLogger, aFg1cSDK, str2, th, false, false, !z, false, 64, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void getMediationNetwork(Function1 function1) {
        Intrinsics.checkNotNullParameter(function1, "");
        k kVar = getMediationNetwork;
        Object value = kVar.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "");
        synchronized (((Set) value)) {
            try {
                Object value2 = kVar.getValue();
                Intrinsics.checkNotNullExpressionValue(value2, "");
                Iterator it2 = ((Set) value2).iterator();
                while (it2.hasNext()) {
                    function1.invoke((AFg1gSDK) it2.next());
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @InterfaceC4935d
    public static final void afErrorLog(String str, Throwable th, boolean z) {
        AFLogger aFLogger = INSTANCE;
        AFg1cSDK aFg1cSDK = AFg1cSDK.OTHER;
        if (str == null || StringsKt.O(str)) {
            str = "null";
        }
        String str2 = str;
        if (th == null) {
            th = new NullPointerException("Invoked with null Throwable");
        }
        AFg1gSDK.e$default(aFLogger, aFg1cSDK, str2, th, false, z, false, false, 104, null);
    }

    @InterfaceC4935d
    public static final void afErrorLog(String str, Throwable th, boolean z, boolean z2) {
        AFLogger aFLogger = INSTANCE;
        AFg1cSDK aFg1cSDK = AFg1cSDK.OTHER;
        if (str == null || StringsKt.O(str)) {
            str = "null";
        }
        String str2 = str;
        if (th == null) {
            th = new NullPointerException("Invoked with null Throwable");
        }
        AFg1gSDK.e$default(aFLogger, aFg1cSDK, str2, th, false, z, z2, false, 72, null);
    }
}
