package androidx.compose.ui.platform;

import android.os.Looper;
import android.view.Choreographer;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3224o6;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class O extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public static final O b = new O(0, 0);
    public static final O c = new O(0, 1);
    public static final O d = new O(0, 2);
    public static final O e = new O(0, 3);
    public static final O f = new O(0, 4);
    public static final O g = new O(0, 5);
    public static final O h = new O(0, 6);
    public static final O i = new O(0, 7);
    public static final O j = new O(0, 8);
    public static final O k = new O(0, 9);
    public static final O l = new O(0, 10);
    public static final O m = new O(0, 11);
    public static final O n = new O(0, 12);
    public static final O o = new O(0, 13);
    public static final O p = new O(0, 14);
    public static final O q = new O(0, 15);
    public static final O r = new O(0, 16);
    public static final O s = new O(0, 17);
    public static final O t = new O(0, 18);
    public static final O u = new O(0, 19);
    public static final O v = new O(0, 20);
    public static final O w = new O(0, 21);
    public static final O x = new O(0, 22);
    public static final O y = new O(0, 23);
    public static final O z = new O(0, 24);
    public static final O A = new O(0, 25);
    public static final O B = new O(0, 26);
    public static final O C = new O(0, 27);
    public static final O D = new O(0, 28);

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ O(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        Choreographer choreographer;
        switch (this.a) {
            case 0:
                AndroidCompositionLocals_androidKt.b("LocalConfiguration");
                throw null;
            case 1:
                AndroidCompositionLocals_androidKt.b("LocalContext");
                throw null;
            case 2:
                AndroidCompositionLocals_androidKt.b("LocalImageVectorCache");
                throw null;
            case 3:
                AndroidCompositionLocals_androidKt.b("LocalResourceIdCache");
                throw null;
            case 4:
                AndroidCompositionLocals_androidKt.b("LocalSavedStateRegistryOwner");
                throw null;
            case 5:
                AndroidCompositionLocals_androidKt.b("LocalView");
                throw null;
            case 6:
                if (Looper.myLooper() == Looper.getMainLooper()) {
                    choreographer = Choreographer.getInstance();
                } else {
                    kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
                    choreographer = (Choreographer) kotlinx.coroutines.E.D(kotlinx.coroutines.internal.m.a, new X(2, null));
                }
                Z z2 = new Z(choreographer, AbstractC3224o6.b(Looper.getMainLooper()));
                return z2.plus(z2.k);
            case 7:
            case 8:
                return null;
            case 9:
                AbstractC0955m0.b("LocalAutofillTree");
                throw null;
            case 10:
                AbstractC0955m0.b("LocalClipboardManager");
                throw null;
            case 11:
                AbstractC0955m0.b("LocalDensity");
                throw null;
            case 12:
                AbstractC0955m0.b("LocalFocusManager");
                throw null;
            case 13:
                AbstractC0955m0.b("LocalFontFamilyResolver");
                throw null;
            case 14:
                AbstractC0955m0.b("LocalFontLoader");
                throw null;
            case 15:
                AbstractC0955m0.b("LocalGraphicsContext");
                throw null;
            case 16:
                AbstractC0955m0.b("LocalHapticFeedback");
                throw null;
            case 17:
                AbstractC0955m0.b("LocalInputManager");
                throw null;
            case 18:
                AbstractC0955m0.b("LocalLayoutDirection");
                throw null;
            case 19:
                return null;
            case 20:
                return Boolean.FALSE;
            case 21:
            case EventType.WINDOW_STATE /* 22 */:
                return null;
            case EventType.AUDIO /* 23 */:
                AbstractC0955m0.b("LocalTextToolbar");
                throw null;
            case EventType.VIDEO /* 24 */:
                AbstractC0955m0.b("LocalUriHandler");
                throw null;
            case EventType.SUBS /* 25 */:
                AbstractC0955m0.b("LocalViewConfiguration");
                throw null;
            case EventType.CDN /* 26 */:
                AbstractC0955m0.b("LocalWindowInfo");
                throw null;
            case 27:
                return Boolean.FALSE;
            default:
                return null;
        }
    }
}
