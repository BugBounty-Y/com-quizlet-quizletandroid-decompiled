package com.onetrust.otpublishers.headless.Internal.Network;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;

/* loaded from: classes2.dex */
public class ConsentUploadWorker extends Worker {
    public final Context e;

    public ConsentUploadWorker(@NonNull Context context, @NonNull WorkerParameters workerParameters) {
        super(context, workerParameters);
        this.e = context;
        OTLogger.c("CPWorker", 4, "Consent logging");
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0128  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0133  */
    @Override // androidx.work.Worker
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.work.x doWork() {
        /*
            Method dump skipped, instructions count: 632
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Network.ConsentUploadWorker.doWork():androidx.work.x");
    }
}
