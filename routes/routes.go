// This file is part of ezBastion.

//     ezBastion is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.

//     ezBastion is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.

//     You should have received a copy of the GNU Affero General Public License
//     along with ezBastion.  If not, see <https://www.gnu.org/licenses/>.

package routes

import (
	"github.com/ezbastion/ezb_vault/ctrl"

	"github.com/gin-gonic/gin"
)

func Routes(route *gin.Engine) {

	KV := route.Group("")
	{
		KV.GET("/", ctrl.GetAll)
		KV.GET("/:name", ctrl.GetVal)
		KV.POST("/", ctrl.AddVal)
		KV.PUT("/:name", ctrl.UpdateVal)
		KV.DELETE("/:name", ctrl.DeleteVal)
	}
}
