package androidx.work.impl.constraints;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import androidx.work.z;
import com.google.android.gms.internal.ads.C2010ed;
import com.google.android.gms.internal.ads.C2928zr;
import com.google.android.gms.internal.ads.S4;
import java.io.UnsupportedEncodingException;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends ConnectivityManager.NetworkCallback {
    public static final /* synthetic */ int c = 0;
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public void onAvailable(Network network) {
        switch (this.a) {
            case 2:
                com.bumptech.glide.util.m.f().post(new com.bumptech.glide.manager.o(true, 0, this));
                break;
            case 3:
            default:
                super.onAvailable(network);
                break;
            case 4:
                ((C2010ed) this.b).o.set(true);
                break;
            case 5:
                C2928zr.b((C2928zr) this.b, true);
                break;
        }
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        i iVarA;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(network, "network");
                Intrinsics.checkNotNullParameter(networkCapabilities, "networkCapabilities");
                z zVarC = z.c();
                int i = o.a;
                zVarC.getClass();
                ((androidx.compose.ui.viewinterop.b) this.b).invoke(a.a);
                return;
            case 1:
                Intrinsics.checkNotNullParameter(network, "network");
                Intrinsics.checkNotNullParameter(networkCapabilities, "capabilities");
                z zVarC2 = z.c();
                String str = androidx.work.impl.constraints.trackers.h.a;
                Objects.toString(networkCapabilities);
                zVarC2.getClass();
                int i2 = Build.VERSION.SDK_INT;
                androidx.work.impl.constraints.trackers.g gVar = (androidx.work.impl.constraints.trackers.g) this.b;
                if (i2 >= 28) {
                    Intrinsics.checkNotNullParameter(networkCapabilities, "<this>");
                    iVarA = new i(networkCapabilities.hasCapability(12), networkCapabilities.hasCapability(16), !networkCapabilities.hasCapability(11), networkCapabilities.hasCapability(18));
                } else {
                    iVarA = androidx.work.impl.constraints.trackers.h.a(gVar.f);
                }
                gVar.d(iVarA);
                return;
            case 2:
            default:
                super.onCapabilitiesChanged(network, networkCapabilities);
                return;
            case 3:
                synchronized (S4.class) {
                    ((S4) this.b).b = networkCapabilities;
                }
                return;
        }
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onLost(Network network) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(network, "network");
                z zVarC = z.c();
                int i = o.a;
                zVarC.getClass();
                ((androidx.compose.ui.viewinterop.b) this.b).invoke(new b(7));
                return;
            case 1:
                Intrinsics.checkNotNullParameter(network, "network");
                z zVarC2 = z.c();
                String str = androidx.work.impl.constraints.trackers.h.a;
                zVarC2.getClass();
                androidx.work.impl.constraints.trackers.g gVar = (androidx.work.impl.constraints.trackers.g) this.b;
                gVar.d(androidx.work.impl.constraints.trackers.h.a(gVar.f));
                return;
            case 2:
                com.bumptech.glide.util.m.f().post(new com.bumptech.glide.manager.o(false, 0, this));
                return;
            case 3:
                synchronized (S4.class) {
                    ((S4) this.b).b = null;
                }
                return;
            case 4:
                ((C2010ed) this.b).o.set(false);
                return;
            default:
                C2928zr.b((C2928zr) this.b, false);
                return;
        }
    }

    public d(androidx.compose.ui.viewinterop.b bVar) {
        this.a = 0;
        this.b = bVar;
    }
}
