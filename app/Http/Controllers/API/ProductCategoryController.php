<?php

namespace App\Http\Controllers\API;

use Illuminate\Http\Request;
use App\Models\ProductCategory;
use App\helpers\ResponseFormatter;
use App\Http\Controllers\Controller;

class ProductCategoryController extends Controller
{
    public function all(Request $request)
    {
        $id = $request->input('id');
        $limit = $request->input('limit');
        $name = $request->input('id');
        $show_product = $request->input('show_product');

        if($id)
        {
            $product = ProductCategory::with(['products'])->find($id);

            if ($product) {
                return ResponseFormatter::success(
                    $product,
                    'Data Kategori Berhasil Diambil'
                );
            }else {
                return ResponseFormatter::error(
                    null,
                    'Data Kategori Tidak Ada',
                    404
                );
            }
        }

        $category = ProductCategory::query();

        if ($name){
            $category->where('name', 'like', '%'. $name. '%');
        }

        if ($show_product){
            $category->with('products');
        }

        return ResponseFormatter::success(
            $category->paginate($limit),
            'Data Kategori Berhasil Diambil',
        );
    }
}
