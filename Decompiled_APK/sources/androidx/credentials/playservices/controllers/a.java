package androidx.credentials.playservices.controllers;

import android.content.Intent;
import android.os.Bundle;
import android.os.ResultReceiver;
import androidx.credentials.exceptions.GetCredentialCancellationException;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.exceptions.GetCredentialInterruptedException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.exceptions.NoCredentialException;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public static GetCredentialException a(String str, String str2) {
        if (str != null) {
            int iHashCode = str.hashCode();
            if (iHashCode != -1567968963) {
                if (iHashCode != -154594663) {
                    if (iHashCode == 1996705159 && str.equals("GET_NO_CREDENTIALS")) {
                        return new NoCredentialException(str2);
                    }
                } else if (str.equals("GET_INTERRUPTED")) {
                    return new GetCredentialInterruptedException(str2);
                }
            } else if (str.equals("GET_CANCELED_TAG")) {
                return new GetCredentialCancellationException(str2);
            }
        }
        return new GetCredentialUnknownException(str2);
    }

    public static void b(ResultReceiver resultReceiver, String errName, String errMsg) {
        Intrinsics.checkNotNullParameter(resultReceiver, "<this>");
        Intrinsics.checkNotNullParameter(errName, "errName");
        Intrinsics.checkNotNullParameter(errMsg, "errMsg");
        Bundle bundle = new Bundle();
        bundle.putBoolean("FAILURE_RESPONSE", true);
        bundle.putString("EXCEPTION_TYPE", errName);
        bundle.putString("EXCEPTION_MESSAGE", errMsg);
        resultReceiver.send(SubsamplingScaleImageView.TILE_SIZE_AUTO, bundle);
    }

    public static void c(ResultReceiver resultReceiver, int i, int i2, Intent intent) {
        Intrinsics.checkNotNullParameter(resultReceiver, "<this>");
        Bundle bundle = new Bundle();
        bundle.putBoolean("FAILURE_RESPONSE", false);
        bundle.putInt("ACTIVITY_REQUEST_CODE", i);
        bundle.putParcelable("RESULT_DATA", intent);
        resultReceiver.send(i2, bundle);
    }
}
