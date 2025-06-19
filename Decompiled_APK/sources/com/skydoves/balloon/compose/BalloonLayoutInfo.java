package com.skydoves.balloon.compose;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonLayoutInfo {
    public static final int $stable = 0;
    private final int height;
    private final int width;
    private final float x;
    private final float y;

    public BalloonLayoutInfo(float f, float f2, int i, int i2) {
        this.x = f;
        this.y = f2;
        this.width = i;
        this.height = i2;
    }

    public static /* synthetic */ BalloonLayoutInfo copy$default(BalloonLayoutInfo balloonLayoutInfo, float f, float f2, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            f = balloonLayoutInfo.x;
        }
        if ((i3 & 2) != 0) {
            f2 = balloonLayoutInfo.y;
        }
        if ((i3 & 4) != 0) {
            i = balloonLayoutInfo.width;
        }
        if ((i3 & 8) != 0) {
            i2 = balloonLayoutInfo.height;
        }
        return balloonLayoutInfo.copy(f, f2, i, i2);
    }

    public final float component1() {
        return this.x;
    }

    public final float component2() {
        return this.y;
    }

    public final int component3() {
        return this.width;
    }

    public final int component4() {
        return this.height;
    }

    @NotNull
    public final BalloonLayoutInfo copy(float f, float f2, int i, int i2) {
        return new BalloonLayoutInfo(f, f2, i, i2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BalloonLayoutInfo)) {
            return false;
        }
        BalloonLayoutInfo balloonLayoutInfo = (BalloonLayoutInfo) obj;
        return Float.compare(this.x, balloonLayoutInfo.x) == 0 && Float.compare(this.y, balloonLayoutInfo.y) == 0 && this.width == balloonLayoutInfo.width && this.height == balloonLayoutInfo.height;
    }

    public final int getHeight() {
        return this.height;
    }

    public final int getWidth() {
        return this.width;
    }

    public final float getX() {
        return this.x;
    }

    public final float getY() {
        return this.y;
    }

    public int hashCode() {
        return Integer.hashCode(this.height) + d0.b(this.width, android.support.v4.media.session.a.b(Float.hashCode(this.x) * 31, this.y, 31), 31);
    }

    @NotNull
    public String toString() {
        return "BalloonLayoutInfo(x=" + this.x + ", y=" + this.y + ", width=" + this.width + ", height=" + this.height + ")";
    }
}
