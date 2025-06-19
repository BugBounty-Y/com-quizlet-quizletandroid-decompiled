package androidx.lifecycle.compose;

import android.os.StatFs;
import androidx.compose.runtime.B;
import androidx.compose.runtime.X0;
import androidx.lifecycle.s0;
import androidx.navigation.C1265a;
import coil3.compose.m;
import coil3.compose.r;
import coil3.disk.i;
import com.braze.Braze;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j;
import java.io.File;
import java.util.Arrays;
import java.util.ServiceConfigurationError;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.K;
import kotlin.ranges.l;
import kotlin.sequences.q;
import okhttp3.A;
import okio.n;
import okio.t;
import okio.x;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        ServiceConfigurationError serviceConfigurationError;
        switch (this.a) {
            case 0:
                throw new IllegalStateException("CompositionLocal LocalLifecycleOwner not present");
            case 1:
                B b = androidx.lifecycle.viewmodel.compose.a.a;
                return null;
            case 2:
                return new s0();
            case 3:
                com.airbnb.lottie.network.d dVar = new com.airbnb.lottie.network.d(14);
                dVar.c(K.a(androidx.navigation.internal.b.class), new C1265a(19));
                return dVar.e();
            case 4:
                throw new IllegalStateException("CompositionLocal LocalSavedStateRegistryOwner not present");
            case 5:
                X0 x0 = r.a;
                return coil3.compose.b.a;
            case 6:
                return m.a;
            case 7:
                t tVar = n.a;
                kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
                x xVarE = n.b.e("coil3_disk_cache");
                long jD = 10485760;
                try {
                    File fileG = xVarE.g();
                    fileG.mkdir();
                    StatFs statFs = new StatFs(fileG.getAbsolutePath());
                    jD = l.d((long) (0.02d * statFs.getBlockSizeLong() * statFs.getBlockCountLong()), 10485760L, 262144000L);
                } catch (Exception unused) {
                }
                return new i(jD, nVar, tVar, xVarE);
            case 8:
                return coil3.network.c.a;
            case 9:
                return new coil3.network.okhttp.internal.b(new A());
            case 10:
                try {
                    return AbstractC3473j.b(q.j(kotlin.sequences.n.b(Arrays.asList(new coil3.network.okhttp.internal.d()).iterator())));
                } finally {
                }
            case 11:
                try {
                    return AbstractC3473j.b(q.j(kotlin.sequences.n.b(Arrays.asList(new coil3.util.b[0]).iterator())));
                } finally {
                }
            case 12:
                return Braze.logPushNotificationActionClicked$lambda$67$lambda$66();
            case 13:
                return Braze.logPushNotificationActionClicked$lambda$67$lambda$65();
            case 14:
                return Braze.logPushNotificationActionClicked$lambda$67$lambda$64();
            case 15:
                return Braze.changeUser$lambda$138$lambda$131();
            case 16:
                return Braze.handleInternalBannerRefresh$lambda$190();
            case 17:
                return Braze.refreshFeatureFlags$lambda$84();
            case 18:
                return Braze.openSession$lambda$38();
            case 19:
                return Braze.schedulePushDelivery$lambda$202();
            case 20:
                return Braze._set_registeredPushToken_$lambda$36$lambda$34();
            case 21:
                return Braze.isEphemeralEventKey$lambda$217();
            case EventType.WINDOW_STATE /* 22 */:
                return Braze.logPurchase$lambda$54$lambda$52();
            case EventType.AUDIO /* 23 */:
                return Braze.logPurchase$lambda$54$lambda$53();
            case EventType.VIDEO /* 24 */:
                return Braze.refreshFeatureFlags$lambda$86$lambda$85();
            case EventType.SUBS /* 25 */:
                return Braze.getCachedContentCards$lambda$144();
            case EventType.CDN /* 26 */:
                return Braze._get_cachedContentCardsUpdatedEvent_$lambda$37();
            case 27:
                return Braze.requestContentCardsRefresh$lambda$79();
            case 28:
                return Braze.requestFeedRefreshFromCache$lambda$75();
            default:
                return Braze._init_$lambda$0();
        }
    }
}
