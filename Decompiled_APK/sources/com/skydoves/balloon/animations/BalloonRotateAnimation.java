package com.skydoves.balloon.animations;

import android.graphics.Camera;
import android.graphics.Matrix;
import android.view.animation.Animation;
import android.view.animation.Transformation;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonRotateAnimation extends Animation {
    private final float degreeX;
    private final float degreeY;
    private final float degreeZ;
    private float height;
    private float width;

    @Metadata
    public static final class Builder {
        public int degreeX;
        public int degreeZ;

        @NotNull
        public BalloonRotateDirection direction = BalloonRotateDirection.RIGHT;
        public int turns = 1;
        public int loops = -1;
        public int speeds = 2500;

        @NotNull
        public final BalloonRotateAnimation build() {
            return new BalloonRotateAnimation(this, null);
        }

        @NotNull
        public final Builder setDegreeX(int i) {
            this.degreeX = i;
            return this;
        }

        @NotNull
        public final Builder setDegreeZ(int i) {
            this.degreeZ = i;
            return this;
        }

        @NotNull
        public final Builder setDirection(@NotNull BalloonRotateDirection rotateDirection) {
            Intrinsics.checkNotNullParameter(rotateDirection, "rotateDirection");
            this.direction = rotateDirection;
            return this;
        }

        @NotNull
        public final Builder setLoops(int i) {
            this.loops = i;
            return this;
        }

        @NotNull
        public final Builder setSpeeds(int i) {
            this.speeds = i;
            return this;
        }

        @NotNull
        public final Builder setTurns(int i) {
            this.turns = i;
            return this;
        }
    }

    public /* synthetic */ BalloonRotateAnimation(Builder builder, DefaultConstructorMarker defaultConstructorMarker) {
        this(builder);
    }

    @Override // android.view.animation.Animation
    public void applyTransformation(float f, @NotNull Transformation transformation) {
        Intrinsics.checkNotNullParameter(transformation, "transformation");
        float f2 = this.degreeX * f;
        float f3 = this.degreeY * f;
        float f4 = this.degreeZ * f;
        Matrix matrix = transformation.getMatrix();
        Camera camera = new Camera();
        camera.save();
        camera.rotateX(f2);
        camera.rotateY(f3);
        camera.rotateZ(f4);
        camera.getMatrix(matrix);
        camera.restore();
        matrix.preTranslate(-this.width, -this.height);
        matrix.postTranslate(this.width, this.height);
    }

    @Override // android.view.animation.Animation
    public void initialize(int i, int i2, int i3, int i4) {
        super.initialize(i, i2, i3, i4);
        this.width = i * 0.5f;
        this.height = i2 * 0.5f;
    }

    private BalloonRotateAnimation(Builder builder) {
        this.degreeX = builder.degreeX;
        this.degreeY = builder.turns * 360 * builder.direction.getValue();
        this.degreeZ = builder.degreeZ;
        setDuration(builder.speeds);
        int i = builder.loops;
        setRepeatCount(i != -1 ? i - 1 : -1);
    }
}
