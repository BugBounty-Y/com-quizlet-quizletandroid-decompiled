
// Do not edit directly
// See https://github.com/quizlet/quizlet-design-tokens for code generation


package com.quizlet.ui.resources.designsystem.generated

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Easing

interface RefAnimEase {
    
    /** Anim Ease of 0.30, 0.00, 0.44, 1.00 */
    val refAnimEaseEnter: Easing
    
    /** Anim Ease of 0.35, 1.40, 0.25, 1.00 */
    val refAnimEaseEnterSpring: Easing
    
    /** Anim Ease of 0.49, 0.00, 0.68, 1.00 */
    val refAnimEaseExit: Easing
    
    /** Anim Ease of 0.40, 0.00, 0.60, -0.40 */
    val refAnimEaseExitSpring: Easing
    
    /** Anim Ease of 0.37, 0.00, 0.53, 1.00 */
    val refAnimEasePersist: Easing
    
    /** Anim Ease of 0.35, 1.40, 0.25, 1.00 */
    val refAnimEasePersistSpring: Easing
    
    /** Anim Ease of 0.35, 0.00, 0.50, 1.00 */
    val refAnimEaseFade: Easing

    companion object : RefAnimEase {
        override val refAnimEaseEnter = CubicBezierEasing(0.30f, 0.00f, 0.44f, 1.00f)
        override val refAnimEaseEnterSpring = CubicBezierEasing(0.35f, 1.40f, 0.25f, 1.00f)
        override val refAnimEaseExit = CubicBezierEasing(0.49f, 0.00f, 0.68f, 1.00f)
        override val refAnimEaseExitSpring = CubicBezierEasing(0.40f, 0.00f, 0.60f, -0.40f)
        override val refAnimEasePersist = CubicBezierEasing(0.37f, 0.00f, 0.53f, 1.00f)
        override val refAnimEasePersistSpring = CubicBezierEasing(0.35f, 1.40f, 0.25f, 1.00f)
        override val refAnimEaseFade = CubicBezierEasing(0.35f, 0.00f, 0.50f, 1.00f)
    }
}
