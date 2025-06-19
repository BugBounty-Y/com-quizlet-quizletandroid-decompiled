package androidx.compose.ui.graphics;

import android.graphics.BlendModeColorFilter;
import com.comscore.streaming.EventType;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.graphics.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0854n {
    public static final C0854n a = new C0854n();

    @NotNull
    public final BlendModeColorFilter a(long j, int i) {
        AbstractC0842b.f();
        return AbstractC0842b.e(F.A(j), F.v(i));
    }

    @NotNull
    public final C0853m b(@NotNull BlendModeColorFilter blendModeColorFilter) {
        int i;
        long jC = F.c(blendModeColorFilter.getColor());
        switch (AbstractC0843c.a[blendModeColorFilter.getMode().ordinal()]) {
            case 1:
                i = 0;
                break;
            case 2:
                i = 1;
                break;
            case 3:
                i = 2;
                break;
            case 4:
            default:
                i = 3;
                break;
            case 5:
                i = 4;
                break;
            case 6:
                i = 5;
                break;
            case 7:
                i = 6;
                break;
            case 8:
                i = 7;
                break;
            case 9:
                i = 8;
                break;
            case 10:
                i = 9;
                break;
            case 11:
                i = 10;
                break;
            case 12:
                i = 11;
                break;
            case 13:
                i = 12;
                break;
            case 14:
                i = 13;
                break;
            case 15:
                i = 14;
                break;
            case 16:
                i = 15;
                break;
            case 17:
                i = 16;
                break;
            case 18:
                i = 17;
                break;
            case 19:
                i = 18;
                break;
            case 20:
                i = 19;
                break;
            case 21:
                i = 20;
                break;
            case EventType.WINDOW_STATE /* 22 */:
                i = 21;
                break;
            case EventType.AUDIO /* 23 */:
                i = 22;
                break;
            case EventType.VIDEO /* 24 */:
                i = 23;
                break;
            case EventType.SUBS /* 25 */:
                i = 24;
                break;
            case EventType.CDN /* 26 */:
                i = 25;
                break;
            case 27:
                i = 26;
                break;
            case 28:
                i = 27;
                break;
            case 29:
                i = 28;
                break;
        }
        return new C0853m(jC, i, blendModeColorFilter);
    }
}
