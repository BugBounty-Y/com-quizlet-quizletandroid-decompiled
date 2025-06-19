package com.google.mlkit.vision.documentscanner;

import android.net.Uri;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class GmsDocumentScanningResult implements Parcelable {

    public static abstract class Page implements Parcelable {
        public abstract Uri a();
    }

    public static abstract class Pdf implements Parcelable {
        public abstract int a();
    }

    public static GmsDocumentScanningResult c(ArrayList arrayList, Uri uri, int i) {
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(new zzg((Uri) it2.next()));
        }
        return new zze(arrayList2, uri != null ? new zzi(uri, i) : null);
    }

    public abstract List a();

    public abstract Pdf b();
}
