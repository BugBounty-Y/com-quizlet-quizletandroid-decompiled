package androidx.privacysandbox.ads.adservices.java.topics;

import android.content.Context;
import android.os.Build;
import androidx.camera.lifecycle.d;
import androidx.privacysandbox.ads.adservices.topics.e;
import androidx.privacysandbox.ads.adservices.topics.f;
import androidx.privacysandbox.ads.adservices.topics.g;
import androidx.privacysandbox.ads.adservices.topics.i;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.internal.m;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class b {
    public final i a;

    public b(i mTopicsManager) {
        Intrinsics.checkNotNullParameter(mTopicsManager, "mTopicsManager");
        this.a = mTopicsManager;
    }

    public static final b a(Context context) {
        i fVar;
        Object objInvoke;
        Object objInvoke2;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        int i = Build.VERSION.SDK_INT;
        androidx.privacysandbox.ads.adservices.internal.b bVar = androidx.privacysandbox.ads.adservices.internal.b.a;
        if ((i >= 33 ? bVar.a() : 0) >= 11) {
            fVar = new e(context);
        } else {
            if ((i >= 33 ? bVar.a() : 0) >= 5) {
                fVar = new g(context);
            } else {
                if ((i >= 33 ? bVar.a() : 0) == 4) {
                    fVar = new f(context);
                } else {
                    androidx.privacysandbox.ads.adservices.internal.a aVar = androidx.privacysandbox.ads.adservices.internal.a.a;
                    if (((i == 31 || i == 32) ? aVar.a() : 0) >= 11) {
                        d manager = new d(context, 2);
                        Intrinsics.checkNotNullParameter(context, "context");
                        Intrinsics.checkNotNullParameter("TopicsManager", "tag");
                        Intrinsics.checkNotNullParameter(manager, "manager");
                        try {
                            objInvoke2 = manager.invoke(context);
                        } catch (NoClassDefFoundError unused) {
                            int i2 = Build.VERSION.SDK_INT;
                            if (i2 == 31 || i2 == 32) {
                                aVar.a();
                            }
                            objInvoke2 = null;
                        }
                        fVar = (i) objInvoke2;
                    } else {
                        if (((i == 31 || i == 32) ? aVar.a() : 0) >= 9) {
                            d manager2 = new d(context, 3);
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intrinsics.checkNotNullParameter("TopicsManager", "tag");
                            Intrinsics.checkNotNullParameter(manager2, "manager");
                            try {
                                objInvoke = manager2.invoke(context);
                            } catch (NoClassDefFoundError unused2) {
                                int i3 = Build.VERSION.SDK_INT;
                                if (i3 == 31 || i3 == 32) {
                                    aVar.a();
                                }
                                objInvoke = null;
                            }
                            fVar = (i) objInvoke;
                        } else {
                            fVar = null;
                        }
                    }
                }
            }
        }
        if (fVar != null) {
            return new b(fVar);
        }
        return null;
    }

    @NotNull
    public com.google.common.util.concurrent.e b(@NotNull androidx.privacysandbox.ads.adservices.topics.a request) {
        Intrinsics.checkNotNullParameter(request, "request");
        kotlinx.coroutines.scheduling.e eVar = O.a;
        return T1.e(E.f(E.c(m.a), null, new a(this, request, null), 3));
    }
}
