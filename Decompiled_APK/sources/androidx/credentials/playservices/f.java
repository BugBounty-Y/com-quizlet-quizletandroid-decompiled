package androidx.credentials.playservices;

import android.app.PendingIntent;
import android.content.IntentSender;
import android.os.ResultReceiver;
import com.google.android.gms.auth.api.identity.BeginSignInResult;
import com.google.android.gms.auth.api.identity.SavePasswordResult;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class f extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ HiddenActivity b;
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(HiddenActivity hiddenActivity, int i, int i2) {
        super(1);
        this.a = i2;
        this.b = hiddenActivity;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                HiddenActivity hiddenActivity = this.b;
                BeginSignInResult beginSignInResult = (BeginSignInResult) obj;
                try {
                    hiddenActivity.b = true;
                    hiddenActivity.startIntentSenderForResult(beginSignInResult.a.getIntentSender(), this.c, null, 0, 0, 0, null);
                } catch (IntentSender.SendIntentException e) {
                    ResultReceiver resultReceiver = hiddenActivity.a;
                    Intrinsics.d(resultReceiver);
                    hiddenActivity.a(resultReceiver, "GET_UNKNOWN", "During begin sign in, one tap ui intent sender failure: " + e.getMessage());
                }
                break;
            case 1:
                HiddenActivity hiddenActivity2 = this.b;
                SavePasswordResult savePasswordResult = (SavePasswordResult) obj;
                try {
                    hiddenActivity2.b = true;
                    hiddenActivity2.startIntentSenderForResult(savePasswordResult.a.getIntentSender(), this.c, null, 0, 0, 0, null);
                } catch (IntentSender.SendIntentException e2) {
                    ResultReceiver resultReceiver2 = hiddenActivity2.a;
                    Intrinsics.d(resultReceiver2);
                    hiddenActivity2.a(resultReceiver2, "CREATE_UNKNOWN", "During save password, found UI intent sender failure: " + e2.getMessage());
                }
                break;
            case 2:
                HiddenActivity hiddenActivity3 = this.b;
                PendingIntent result = (PendingIntent) obj;
                Intrinsics.checkNotNullParameter(result, "result");
                try {
                    hiddenActivity3.b = true;
                    hiddenActivity3.startIntentSenderForResult(result.getIntentSender(), this.c, null, 0, 0, 0, null);
                } catch (IntentSender.SendIntentException e3) {
                    ResultReceiver resultReceiver3 = hiddenActivity3.a;
                    Intrinsics.d(resultReceiver3);
                    hiddenActivity3.a(resultReceiver3, "CREATE_UNKNOWN", "During public key credential, found IntentSender failure on public key creation: " + e3.getMessage());
                }
                break;
            default:
                HiddenActivity hiddenActivity4 = this.b;
                PendingIntent pendingIntent = (PendingIntent) obj;
                try {
                    hiddenActivity4.b = true;
                    hiddenActivity4.startIntentSenderForResult(pendingIntent.getIntentSender(), this.c, null, 0, 0, 0, null);
                } catch (IntentSender.SendIntentException e4) {
                    ResultReceiver resultReceiver4 = hiddenActivity4.a;
                    Intrinsics.d(resultReceiver4);
                    hiddenActivity4.a(resultReceiver4, "GET_UNKNOWN", "During get sign-in intent, one tap ui intent sender failure: " + e4.getMessage());
                }
                break;
        }
        return Unit.a;
    }
}
