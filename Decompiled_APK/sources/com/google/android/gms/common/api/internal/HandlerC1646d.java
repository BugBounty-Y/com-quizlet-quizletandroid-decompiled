package com.google.android.gms.common.api.internal;

import android.os.Message;
import android.util.Log;
import android.util.Pair;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.ads.Ls;

/* renamed from: com.google.android.gms.common.api.internal.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class HandlerC1646d extends Ls {
    @Override // android.os.Handler
    public final void handleMessage(Message message) {
        int i = message.what;
        if (i != 1) {
            if (i == 2) {
                ((BasePendingResult) message.obj).forceFailureUnlessReady(Status.h);
                return;
            }
            StringBuilder sb = new StringBuilder(String.valueOf(i).length() + 34);
            sb.append("Don't know how to handle message: ");
            sb.append(i);
            Log.wtf("BasePendingResult", sb.toString(), new Exception());
            return;
        }
        Pair pair = (Pair) message.obj;
        if (pair.first != null) {
            throw new ClassCastException();
        }
        com.google.android.gms.common.api.k kVar = (com.google.android.gms.common.api.k) pair.second;
        try {
            throw null;
        } catch (RuntimeException e) {
            BasePendingResult.zal(kVar);
            throw e;
        }
    }
}
