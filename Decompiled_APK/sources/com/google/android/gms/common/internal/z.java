package com.google.android.gms.common.internal;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.ConnectionResult;

/* loaded from: classes2.dex */
public final class z extends p {
    public final IBinder g;
    public final /* synthetic */ AbstractC1655e h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(AbstractC1655e abstractC1655e, int i, IBinder iBinder, Bundle bundle) {
        super(abstractC1655e, i, bundle);
        this.h = abstractC1655e;
        this.g = iBinder;
    }

    @Override // com.google.android.gms.common.internal.p
    public final boolean a() throws RemoteException {
        IBinder iBinder = this.g;
        try {
            u.h(iBinder);
            String interfaceDescriptor = iBinder.getInterfaceDescriptor();
            AbstractC1655e abstractC1655e = this.h;
            if (!abstractC1655e.n().equals(interfaceDescriptor)) {
                String strN = abstractC1655e.n();
                Log.w("GmsClient", androidx.compose.ui.node.B.j(new StringBuilder(strN.length() + 34 + String.valueOf(interfaceDescriptor).length()), "service descriptor mismatch: ", strN, " vs. ", interfaceDescriptor));
                return false;
            }
            IInterface iInterfaceD = abstractC1655e.d(iBinder);
            if (iInterfaceD == null || !(abstractC1655e.t(2, 4, iInterfaceD) || abstractC1655e.t(3, 4, iInterfaceD))) {
                return false;
            }
            abstractC1655e.u = null;
            InterfaceC1652b interfaceC1652b = abstractC1655e.o;
            if (interfaceC1652b == null) {
                return true;
            }
            interfaceC1652b.X();
            return true;
        } catch (RemoteException unused) {
            Log.w("GmsClient", "service probably died");
            return false;
        }
    }

    @Override // com.google.android.gms.common.internal.p
    public final void b(ConnectionResult connectionResult) {
        InterfaceC1653c interfaceC1653c = this.h.p;
        if (interfaceC1653c != null) {
            interfaceC1653c.f0(connectionResult);
        }
        System.currentTimeMillis();
    }
}
