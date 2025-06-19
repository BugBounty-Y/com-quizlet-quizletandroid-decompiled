package androidx.credentials.playservices.controllers;

import android.content.Context;
import android.content.Intent;
import android.os.Parcel;
import android.os.ResultReceiver;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public class b {
    public static final a a = new a();
    public static final Set b;
    public static final int c;

    static {
        Integer[] elements = {7, 20};
        Intrinsics.checkNotNullParameter(elements, "elements");
        b = C4933y.T(elements);
        c = 1;
    }

    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public static void a(ResultReceiver resultReceiver, Intent hiddenIntent, String typeTag) {
        Intrinsics.checkNotNullParameter(resultReceiver, "resultReceiver");
        Intrinsics.checkNotNullParameter(hiddenIntent, "hiddenIntent");
        Intrinsics.checkNotNullParameter(typeTag, "typeTag");
        hiddenIntent.putExtra("TYPE", typeTag);
        hiddenIntent.putExtra("ACTIVITY_REQUEST_CODE", c);
        Parcel parcelObtain = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(parcelObtain, "obtain(...)");
        Intrinsics.d(resultReceiver);
        resultReceiver.writeToParcel(parcelObtain, 0);
        parcelObtain.setDataPosition(0);
        ResultReceiver resultReceiver2 = (ResultReceiver) ResultReceiver.CREATOR.createFromParcel(parcelObtain);
        parcelObtain.recycle();
        hiddenIntent.putExtra("RESULT_RECEIVER", resultReceiver2);
        hiddenIntent.setFlags(65536);
    }
}
