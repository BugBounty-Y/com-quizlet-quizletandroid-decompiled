package com.google.android.gms.auth.api.signin.internal;

import android.os.Parcel;
import com.google.android.gms.common.api.Status;

/* loaded from: classes2.dex */
public final class e extends com.google.android.gms.internal.p000authapi.g implements i {
    public final /* synthetic */ int b;
    public final /* synthetic */ f c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, int i) {
        super("com.google.android.gms.auth.api.signin.internal.ISignInCallbacks", 0);
        this.b = i;
        this.c = fVar;
    }

    @Override // com.google.android.gms.auth.api.signin.internal.i
    public void U1(Status status) {
        switch (this.b) {
            case 1:
                this.c.setResult(status);
                return;
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean f3(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 101:
                com.google.android.gms.internal.p000authapi.h.b(parcel);
                throw new UnsupportedOperationException();
            case 102:
                Status status = (Status) com.google.android.gms.internal.p000authapi.h.a(parcel, Status.CREATOR);
                com.google.android.gms.internal.p000authapi.h.b(parcel);
                r2(status);
                break;
            case 103:
                Status status2 = (Status) com.google.android.gms.internal.p000authapi.h.a(parcel, Status.CREATOR);
                com.google.android.gms.internal.p000authapi.h.b(parcel);
                U1(status2);
                break;
            default:
                return false;
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.auth.api.signin.internal.i
    public void r2(Status status) {
        switch (this.b) {
            case 0:
                this.c.setResult(status);
                return;
            default:
                throw new UnsupportedOperationException();
        }
    }
}
