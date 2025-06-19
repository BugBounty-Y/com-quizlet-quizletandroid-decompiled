package com.google.android.gms.internal.gtm;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/* loaded from: classes2.dex */
final class zzpp implements Runnable {
    final /* synthetic */ String zza;
    final /* synthetic */ byte[] zzb;
    final /* synthetic */ zzpq zzc;

    public zzpp(zzpq zzpqVar, String str, byte[] bArr) {
        this.zza = str;
        this.zzb = bArr;
        this.zzc = zzpqVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws IOException {
        FileOutputStream fileOutputStream;
        zzpq zzpqVar = this.zzc;
        String str = this.zza;
        File fileZzb = zzpqVar.zzb(str);
        byte[] bArr = this.zzb;
        try {
            try {
                fileOutputStream = new FileOutputStream(fileZzb);
                try {
                    fileOutputStream.write(bArr);
                } catch (IOException unused) {
                    zzhi.zza("Error writing resource to disk. Removing resource from disk");
                    fileZzb.delete();
                    try {
                        fileOutputStream.close();
                        zzhi.zzd("Resource " + str + " saved on Disk.");
                    } catch (IOException unused2) {
                        zzhi.zza("Error closing stream for writing resource to disk");
                    }
                }
            } catch (FileNotFoundException unused3) {
                zzhi.zza("Error opening resource file for writing");
            }
        } finally {
            try {
                fileOutputStream.close();
                zzhi.zzd("Resource " + str + " saved on Disk.");
            } catch (IOException unused4) {
                zzhi.zza("Error closing stream for writing resource to disk");
            }
        }
    }
}
