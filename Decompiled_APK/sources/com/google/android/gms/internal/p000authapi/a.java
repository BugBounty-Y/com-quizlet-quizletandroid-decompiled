package com.google.android.gms.internal.p000authapi;

import android.app.PendingIntent;
import android.os.Parcel;
import com.google.android.gms.auth.api.identity.BeginSignInResult;
import com.google.android.gms.auth.api.identity.SavePasswordResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3465h3;
import com.google.android.gms.tasks.f;

/* loaded from: classes2.dex */
public final class a extends g {
    public final /* synthetic */ int b;
    public final /* synthetic */ f c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(f fVar, int i) {
        super("com.google.android.gms.auth.api.identity.internal.ISavePasswordCallback", 0);
        this.b = i;
        switch (i) {
            case 1:
                this.c = fVar;
                super("com.google.android.gms.auth.api.identity.internal.IBeginSignInCallback", 0);
                break;
            case 2:
                this.c = fVar;
                super("com.google.android.gms.auth.api.identity.internal.IGetSignInIntentCallback", 0);
                break;
            default:
                this.c = fVar;
                break;
        }
    }

    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean f3(int i, Parcel parcel, Parcel parcel2) {
        switch (this.b) {
            case 0:
                if (i == 1) {
                    Status status = (Status) h.a(parcel, Status.CREATOR);
                    SavePasswordResult savePasswordResult = (SavePasswordResult) h.a(parcel, SavePasswordResult.CREATOR);
                    h.b(parcel);
                    AbstractC3465h3.c(status, savePasswordResult, this.c);
                    break;
                }
                break;
            case 1:
                if (i == 1) {
                    Status status2 = (Status) h.a(parcel, Status.CREATOR);
                    BeginSignInResult beginSignInResult = (BeginSignInResult) h.a(parcel, BeginSignInResult.CREATOR);
                    h.b(parcel);
                    AbstractC3465h3.c(status2, beginSignInResult, this.c);
                    break;
                }
                break;
            default:
                if (i == 1) {
                    Status status3 = (Status) h.a(parcel, Status.CREATOR);
                    PendingIntent pendingIntent = (PendingIntent) h.a(parcel, PendingIntent.CREATOR);
                    h.b(parcel);
                    AbstractC3465h3.c(status3, pendingIntent, this.c);
                    break;
                }
                break;
        }
        return true;
    }
}
