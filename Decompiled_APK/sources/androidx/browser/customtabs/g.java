package androidx.browser.customtabs;

import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import androidx.appcompat.widget.V;

/* loaded from: classes.dex */
public final class g extends Binder implements android.support.customtabs.a {
    public final Handler a;
    public final /* synthetic */ a b;

    public g(a aVar) {
        this.b = aVar;
        attachInterface(this, android.support.customtabs.a.N);
        this.a = new Handler(Looper.getMainLooper());
    }

    @Override // android.os.IInterface
    public final IBinder asBinder() {
        return this;
    }

    @Override // android.os.Binder
    public final boolean onTransact(int i, Parcel parcel, Parcel parcel2, int i2) {
        String str = android.support.customtabs.a.N;
        if (i >= 1 && i <= 16777215) {
            parcel.enforceInterface(str);
        }
        if (i == 1598968902) {
            parcel2.writeString(str);
            return true;
        }
        Handler handler = this.a;
        a aVar = this.b;
        switch (i) {
            case 2:
                int i3 = parcel.readInt();
                Bundle bundle = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new V(this, i3, bundle, 1));
                    return true;
                }
                return true;
            case 3:
                String string = parcel.readString();
                Bundle bundle2 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new d(this, string, bundle2, 0));
                    return true;
                }
                return true;
            case 4:
                Bundle bundle3 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new androidx.camera.core.impl.utils.futures.h(this, false, bundle3, 1));
                }
                parcel2.writeNoException();
                return true;
            case 5:
                String string2 = parcel.readString();
                Bundle bundle4 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new d(this, string2, bundle4, 1));
                }
                parcel2.writeNoException();
                return true;
            case 6:
                int i4 = parcel.readInt();
                Uri uri = (Uri) _COROUTINE.a.f(parcel, Uri.CREATOR);
                boolean z = parcel.readInt() != 0;
                Bundle bundle5 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new e(this, i4, uri, z, bundle5));
                    return true;
                }
                return true;
            case 7:
                Bundle bundleB = aVar == null ? null : aVar.b((Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR), parcel.readString());
                parcel2.writeNoException();
                if (bundleB == null) {
                    parcel2.writeInt(0);
                    return true;
                }
                parcel2.writeInt(1);
                bundleB.writeToParcel(parcel2, 1);
                return true;
            case 8:
                int i5 = parcel.readInt();
                int i6 = parcel.readInt();
                Bundle bundle6 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new f(this, i5, i6, bundle6));
                    return true;
                }
                return true;
            case 9:
                Bundle bundle7 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new c(this, bundle7, 1));
                    return true;
                }
                return true;
            case 10:
                int i7 = parcel.readInt();
                int i8 = parcel.readInt();
                int i9 = parcel.readInt();
                int i10 = parcel.readInt();
                int i11 = parcel.readInt();
                Bundle bundle8 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new c(this, i7, i8, i9, i10, i11, bundle8));
                    return true;
                }
                return true;
            case 11:
                Bundle bundle9 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new c(this, bundle9, 3));
                    return true;
                }
                return true;
            case 12:
                Bundle bundle10 = (Bundle) _COROUTINE.a.f(parcel, Bundle.CREATOR);
                if (aVar != null) {
                    handler.post(new c(this, bundle10, 0));
                    return true;
                }
                return true;
            default:
                return super.onTransact(i, parcel, parcel2, i2);
        }
    }
}
