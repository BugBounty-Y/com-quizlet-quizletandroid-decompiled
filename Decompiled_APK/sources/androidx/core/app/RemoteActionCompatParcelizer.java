package androidx.core.app;

import android.app.PendingIntent;
import android.os.Parcel;
import android.text.TextUtils;
import androidx.core.graphics.drawable.IconCompat;
import java.lang.reflect.InvocationTargetException;

/* loaded from: classes.dex */
public class RemoteActionCompatParcelizer {
    public static RemoteActionCompat read(androidx.versionedparcelable.a aVar) {
        RemoteActionCompat remoteActionCompat = new RemoteActionCompat();
        androidx.versionedparcelable.c cVarH = remoteActionCompat.a;
        boolean z = true;
        if (aVar.e(1)) {
            cVarH = aVar.h();
        }
        remoteActionCompat.a = (IconCompat) cVarH;
        CharSequence charSequence = remoteActionCompat.b;
        if (aVar.e(2)) {
            charSequence = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(((androidx.versionedparcelable.b) aVar).e);
        }
        remoteActionCompat.b = charSequence;
        CharSequence charSequence2 = remoteActionCompat.c;
        if (aVar.e(3)) {
            charSequence2 = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(((androidx.versionedparcelable.b) aVar).e);
        }
        remoteActionCompat.c = charSequence2;
        remoteActionCompat.d = (PendingIntent) aVar.g(remoteActionCompat.d, 4);
        boolean z2 = remoteActionCompat.e;
        if (aVar.e(5)) {
            z2 = ((androidx.versionedparcelable.b) aVar).e.readInt() != 0;
        }
        remoteActionCompat.e = z2;
        boolean z3 = remoteActionCompat.f;
        if (!aVar.e(6)) {
            z = z3;
        } else if (((androidx.versionedparcelable.b) aVar).e.readInt() == 0) {
            z = false;
        }
        remoteActionCompat.f = z;
        return remoteActionCompat;
    }

    public static void write(RemoteActionCompat remoteActionCompat, androidx.versionedparcelable.a aVar) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        aVar.getClass();
        IconCompat iconCompat = remoteActionCompat.a;
        aVar.i(1);
        aVar.l(iconCompat);
        CharSequence charSequence = remoteActionCompat.b;
        aVar.i(2);
        Parcel parcel = ((androidx.versionedparcelable.b) aVar).e;
        TextUtils.writeToParcel(charSequence, parcel, 0);
        CharSequence charSequence2 = remoteActionCompat.c;
        aVar.i(3);
        TextUtils.writeToParcel(charSequence2, parcel, 0);
        aVar.k(remoteActionCompat.d, 4);
        boolean z = remoteActionCompat.e;
        aVar.i(5);
        parcel.writeInt(z ? 1 : 0);
        boolean z2 = remoteActionCompat.f;
        aVar.i(6);
        parcel.writeInt(z2 ? 1 : 0);
    }
}
