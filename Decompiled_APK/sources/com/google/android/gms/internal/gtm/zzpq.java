package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.util.c;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;

/* loaded from: classes2.dex */
public final class zzpq {
    private final Context zza;
    private final ExecutorService zzb;
    private final zzpm zzc;

    public zzpq(Context context) {
        ExecutorService executorServiceZza = zzfx.zza().zza(2);
        zzpm zzpmVar = new zzpm(context);
        this.zza = context;
        this.zzb = executorServiceZza;
        this.zzc = zzpmVar;
    }

    private static final byte[] zzh(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            try {
                try {
                    c.e(inputStream, byteArrayOutputStream, false);
                } catch (IOException unused) {
                    zzhi.zze("Failed to read the resource from disk");
                }
                return byteArrayOutputStream.toByteArray();
            } finally {
                inputStream.close();
            }
        } catch (IOException unused2) {
            zzhi.zze("Error closing stream for reading resource from disk");
            return null;
        }
    }

    private static final String zzi(String str) {
        return "resource_".concat(String.valueOf(str));
    }

    public final long zza(String str) {
        File fileZzb = zzb(str);
        if (fileZzb.exists()) {
            return fileZzb.lastModified();
        }
        return 0L;
    }

    public final File zzb(String str) {
        return new File(this.zza.getDir("google_tagmanager", 0), zzi(str));
    }

    public final void zzc(String str, String str2, zzpa zzpaVar) {
        this.zzb.execute(new zzpo(this, str, str2, zzpaVar));
    }

    public final void zzd(String str, String str2, zzpa zzpaVar) {
        zzhi.zzd("Starting to load a default asset file from Disk.");
        if (str2 == null) {
            zzhi.zzd("Default asset file is not specified. Not proceeding with the loading");
            zzpaVar.zzb(0, 2);
            return;
        }
        try {
            InputStream inputStreamOpen = this.zzc.zza.getAssets().open(str2);
            if (inputStreamOpen != null) {
                zzpaVar.zzc(zzh(inputStreamOpen));
            } else {
                zzpaVar.zzb(0, 2);
            }
        } catch (IOException unused) {
            zzhi.zza("Default asset file not found. " + str + ". Filename: " + str2);
            zzpaVar.zzb(0, 2);
        }
    }

    public final void zze(String str, zzpa zzpaVar) {
        this.zzb.execute(new zzpn(this, str, zzpaVar));
    }

    public final void zzf(String str, zzpa zzpaVar) {
        zzhi.zzd("Starting to load a saved resource file from Disk.");
        try {
            zzpaVar.zzc(zzh(new FileInputStream(zzb(str))));
        } catch (FileNotFoundException unused) {
            zzhi.zza("Saved resource not found: ".concat(zzi(str)));
            zzpaVar.zzb(0, 1);
        }
    }

    public final void zzg(String str, byte[] bArr) {
        this.zzb.execute(new zzpp(this, str, bArr));
    }
}
