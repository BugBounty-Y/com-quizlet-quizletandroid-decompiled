
// Do not edit directly
// See https://github.com/quizlet/quizlet-design-tokens for code generation


package com.quizlet.ui.resources.designsystem.generated

import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

interface RefRadius {
    
    /** Radius of 0 */
    val refRadiusNone: Dp
    
    /** Radius of 4 */
    val refRadiusSmall: Dp
    
    /** Radius of 8 */
    val refRadiusMedium: Dp
    
    /** Radius of 16 */
    val refRadiusLarge: Dp
    
    /** Radius of 24 */
    val refRadiusXLarge: Dp
    
    /** Radius of 200 */
    val refRadiusFull: Dp

    companion object : RefRadius {
        override val refRadiusNone = 0.dp
        override val refRadiusSmall = 4.dp
        override val refRadiusMedium = 8.dp
        override val refRadiusLarge = 16.dp
        override val refRadiusXLarge = 24.dp
        override val refRadiusFull = 200.dp
    }
}
