int sum3(int* arr){
    
    int sum = 0;
    for(int i = 0; i < 3; i++)
        sum += arr[i];
        
    return sum;
}

int sum(int* arr, int N){

    int sum = 0;
    for(int i = 0; i < N; i++)
        sum += arr[i];
        
    return sum;
}

int sum_rec(int* arr, int N){

    if(N == 0)
        return 0;
        
    return arr[0] + sum_rec(arr + 1, N - 1);
}



int main(){
    
    int arr[3] = {1,2,3};
    return sum3(arr) + sum_rec(arr, 3) + sum(arr, 3);
}
