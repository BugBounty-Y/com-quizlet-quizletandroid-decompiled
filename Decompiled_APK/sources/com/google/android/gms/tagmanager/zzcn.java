package com.google.android.gms.tagmanager;

import android.content.Intent;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.dynamic.a;

/* loaded from: classes2.dex */
public interface zzcn extends IInterface {
    void initialize(a aVar, zzck zzckVar, zzcb zzcbVar) throws RemoteException;

    void preview(Intent intent, a aVar) throws RemoteException;

    void previewIntent(Intent intent, a aVar, a aVar2, zzck zzckVar, zzcb zzcbVar) throws RemoteException;
}
